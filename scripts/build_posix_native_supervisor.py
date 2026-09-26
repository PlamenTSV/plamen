#!/usr/bin/env python3
"""Build the CPython native supervisor from retained immutable snapshots.

The builder never imports the result.  Its build key authenticates the exact
compiler command, closed environment, CPython ABI/sysconfig, original source,
descriptor-frozen preprocessed translation unit, consumed header/SDK closure,
toolchain identities, flags and production-vs-TEST_ONLY module identity.
Compiler output is a pre-owned O_EXCL/NOFOLLOW descriptor, not a
compiler-chosen pathname.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
from contextlib import ExitStack
try:
    import fcntl
except ImportError:  # pragma: no cover - rejected by the platform gate
    fcntl = None  # type: ignore[assignment]
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
from types import MappingProxyType, ModuleType
from typing import Any


PRODUCTION_MODULE = "_plamen_native_supervisor"
TEST_ONLY_MODULE = "_plamen_native_supervisor_testonly"
PRODUCTION_CPYTHON_ABI = (3, 12)
SUPPORTED_CPYTHON_ABIS = {(3, 12), (3, 14)}
SUPPORTED_PLATFORMS = {"darwin", "linux"}
MAX_COMPILER_OUTPUT_BYTES = 64 * 1024
MAX_SNAPSHOT_FILES = 4096
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_TOOLCHAIN_MEMBERS = 128
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY_ROOT / "native" / "cpython" / "_plamen_native_supervisor.c"
PROTOCOL_SOURCE = (
    REPOSITORY_ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"
)
DARWIN_RECEIPT_SOURCE = (
    REPOSITORY_ROOT / "native" / "darwin"
    / "plamen_broker_v2_install_receipt.c"
)
LINUX_INSTALL_AUTHORITY_SOURCE = (
    REPOSITORY_ROOT / "scripts" / "linux_native_install_authority.py"
)
NATIVE_HEADER_ROOT = REPOSITORY_ROOT / "native" / "include"

# This is the complete source-side denominator for the first production Darwin
# installation closure.  Missing rows are intentional blockers, not optional
# discovery.  In particular, neither a recursive directory walk nor a newly
# appearing source file may silently enlarge what the release build trusts.
PRODUCTION_DARWIN_SOURCE_ROSTER = (
    ("source_build_dispatch", "scripts/build_posix_native_supervisor.py"),
    ("cpython_extension", "native/cpython/_plamen_native_supervisor.c"),
    ("shared_broker_abi", "native/include/plamen_broker_v2.h"),
    ("broker_protocol_header", "native/posix/plamen_broker_v2_protocol.h"),
    ("broker_protocol", "native/posix/plamen_broker_v2_protocol.c"),
    ("darwin_process_header", "native/darwin/plamen_broker_v2_process.h"),
    ("darwin_process", "native/darwin/plamen_broker_v2_process.c"),
    (
        "darwin_process_custodian_header",
        "native/darwin/plamen_broker_v2_process_custodian.h",
    ),
    (
        "darwin_process_custodian",
        "native/darwin/plamen_broker_v2_process_custodian.c",
    ),
    (
        "darwin_process_custody_daemon_header",
        "native/darwin/plamen_broker_v2_process_custody_daemon.h",
    ),
    (
        "darwin_process_custody_daemon",
        "native/darwin/plamen_broker_v2_process_custody_daemon.c",
    ),
    (
        "darwin_process_custody_client_header",
        "native/darwin/plamen_broker_v2_process_custody_client.h",
    ),
    (
        "darwin_process_custody_client",
        "native/darwin/plamen_broker_v2_process_custody_client.c",
    ),
    (
        "darwin_apple_container_header",
        "native/darwin/plamen_broker_v2_apple_container.h",
    ),
    (
        "darwin_apple_container",
        "native/darwin/plamen_broker_v2_apple_container.c",
    ),
    (
        "darwin_apple_lifecycle_header",
        "native/darwin/plamen_broker_v2_apple_container_lifecycle.h",
    ),
    (
        "darwin_apple_lifecycle",
        "native/darwin/plamen_broker_v2_apple_container_lifecycle.c",
    ),
    (
        "darwin_fuzz_campaign_header",
        "native/darwin/plamen_broker_v2_fuzz_campaign.h",
    ),
    (
        "darwin_fuzz_campaign",
        "native/darwin/plamen_broker_v2_fuzz_campaign.c",
    ),
    (
        "darwin_fuzz_service",
        "native/darwin/plamen_broker_v2_fuzz_service.c",
    ),
    (
        "darwin_tool_custody_header",
        "native/darwin/plamen_broker_v2_tool_custody.h",
    ),
    (
        "darwin_tool_custody",
        "native/darwin/plamen_broker_v2_tool_custody.c",
    ),
    ("darwin_effects_header", "native/darwin/plamen_broker_v2_effects.h"),
    ("darwin_effects", "native/darwin/plamen_broker_v2_effects.c"),
    (
        "darwin_specialized_request_header",
        "native/darwin/plamen_broker_v2_specialized_request.h",
    ),
    (
        "darwin_specialized_request",
        "native/darwin/plamen_broker_v2_specialized_request.c",
    ),
    (
        "darwin_specialized_runtime_authority_header",
        "native/darwin/plamen_broker_v2_specialized_runtime_authority.h",
    ),
    (
        "darwin_specialized_runtime_authority",
        "native/darwin/plamen_broker_v2_specialized_runtime_authority.c",
    ),
    (
        "darwin_specialized_runtime_effects_handoff_header",
        "native/darwin/plamen_broker_v2_specialized_runtime_effects_handoff.h",
    ),
    (
        "darwin_specialized_runtime_effects_handoff",
        "native/darwin/plamen_broker_v2_specialized_runtime_effects_handoff.c",
    ),
    (
        "darwin_specialized_effect_store_header",
        "native/darwin/plamen_broker_v2_specialized_effect_store.h",
    ),
    (
        "darwin_specialized_effect_store",
        "native/darwin/plamen_broker_v2_specialized_effect_store.c",
    ),
    (
        "darwin_specialized_apple_effect_execution_header",
        "native/darwin/plamen_broker_v2_specialized_apple_effect_execution.h",
    ),
    (
        "darwin_specialized_apple_effect_execution",
        "native/darwin/plamen_broker_v2_specialized_apple_effect_execution.c",
    ),
    (
        "darwin_specialized_output_census_header",
        "native/darwin/plamen_broker_v2_specialized_output_census.h",
    ),
    (
        "darwin_specialized_output_census",
        "native/darwin/plamen_broker_v2_specialized_output_census.c",
    ),
    (
        "darwin_specialized_output_receipt_header",
        "native/darwin/plamen_broker_v2_specialized_output_receipt.h",
    ),
    (
        "darwin_specialized_output_receipt",
        "native/darwin/plamen_broker_v2_specialized_output_receipt.c",
    ),
    (
        "darwin_workspace_effects_header",
        "native/darwin/plamen_broker_v2_workspace_effects.h",
    ),
    (
        "darwin_workspace_effects",
        "native/darwin/plamen_broker_v2_workspace_effects.c",
    ),
    (
        "darwin_operations_header",
        "native/darwin/plamen_broker_v2_operations.h",
    ),
    ("darwin_operations", "native/darwin/plamen_broker_v2_operations.c"),
    (
        "darwin_install_receipt_header",
        "native/darwin/plamen_broker_v2_install_receipt.h",
    ),
    (
        "darwin_install_receipt",
        "native/darwin/plamen_broker_v2_install_receipt.c",
    ),
    (
        "darwin_launchd_installer_header",
        "native/darwin/plamen_native_launchd_installer_v2.h",
    ),
    (
        "darwin_launchd_installer",
        "native/darwin/plamen_native_launchd_installer_v2.c",
    ),
    (
        "darwin_launchd_readiness_header",
        "native/darwin/plamen_native_launchd_readiness_v2.h",
    ),
    (
        "darwin_launchd_readiness",
        "native/darwin/plamen_native_launchd_readiness_v2.c",
    ),
    (
        "darwin_install_coordinator_header",
        "native/darwin/plamen_native_install_coordinator_v2.h",
    ),
    (
        "darwin_install_coordinator",
        "native/darwin/plamen_native_install_coordinator_v2.c",
    ),
    (
        "darwin_source_bootstrap_coordinator_header",
        "native/darwin/plamen_native_source_bootstrap_coordinator_v1.h",
    ),
    (
        "darwin_source_bootstrap_coordinator",
        "native/darwin/plamen_native_source_bootstrap_coordinator_v1.c",
    ),
    (
        "darwin_backend_receipt_signer_header",
        "native/darwin/plamen_native_backend_receipt_signer_v1.h",
    ),
    (
        "darwin_backend_receipt_signer",
        "native/darwin/plamen_native_backend_receipt_signer_v1.c",
    ),
    (
        "darwin_backend_receipt_signer_swift",
        "native/darwin/plamen_native_backend_receipt_signer_v1.swift",
    ),
    (
        "darwin_operation4_helper_header",
        "native/darwin/plamen_native_operation4_helper_v1.h",
    ),
    (
        "darwin_operation4_helper",
        "native/darwin/plamen_native_operation4_helper_v1.c",
    ),
    (
        "darwin_evm_static_acquisition_header",
        "native/darwin/plamen_native_evm_static_acquisition_v1.h",
    ),
    (
        "darwin_evm_static_acquisition",
        "native/darwin/plamen_native_evm_static_acquisition_v1.c",
    ),
    (
        "darwin_evm_static_acquisition_swift",
        "native/darwin/plamen_native_evm_static_acquisition_v1.swift",
    ),
    (
        "darwin_evm_static_assets",
        "native/darwin/plamen_native_evm_static_assets_v1.inc",
    ),
    (
        "darwin_fixed_role_acquisition_header",
        "native/darwin/plamen_native_fixed_role_acquisition_v1.h",
    ),
    (
        "darwin_fixed_role_acquisition",
        "native/darwin/plamen_native_fixed_role_acquisition_v1.c",
    ),
    (
        "darwin_code_identity_header",
        "native/darwin/plamen_native_code_identity_v2.h",
    ),
    (
        "darwin_code_identity",
        "native/darwin/plamen_native_code_identity_v2.c",
    ),
    (
        "darwin_deployment_receipt_header",
        "native/darwin/plamen_native_deployment_receipt_v2.h",
    ),
    (
        "darwin_deployment_receipt",
        "native/darwin/plamen_native_deployment_receipt_v2.c",
    ),
    (
        "darwin_service_store_header",
        "native/darwin/plamen_broker_v2_service_store.h",
    ),
    (
        "darwin_service_store",
        "native/darwin/plamen_broker_v2_service_store.c",
    ),
    (
        "native_supervisor_schema",
        "native/darwin/native-supervisor-schema-v2.json",
    ),
    ("outer_entrypoint", "scripts/posix_audit_entrypoint.py"),
    ("report_output_routing", "scripts/report_output_routing.py"),
    (
        "specialized_guest_worker",
        "scripts/posix_specialized_tool_worker.py",
    ),
    (
        "outer_authority_adapter",
        "scripts/posix_native_authority_adapter.py",
    ),
    ("darwin_service", "native/darwin/plamen_broker_v2_service.c"),
    ("darwin_launcher", "native/darwin/plamen_native_launcher.c"),
    (
        "darwin_artifact_export_header",
        "native/darwin/plamen_broker_v2_artifact_export.h",
    ),
    (
        "darwin_artifact_export",
        "native/darwin/plamen_broker_v2_artifact_export.c",
    ),
    (
        "darwin_image_member_receipt_header",
        "native/darwin/plamen_native_image_member_receipt_v2.h",
    ),
    (
        "darwin_image_member_receipt",
        "native/darwin/plamen_native_image_member_receipt_v2.c",
    ),
    ("launchd_manifest", "native/darwin/com.plamen.audit.broker.v2.plist"),
    (
        "custody_launchd_manifest",
        "native/darwin/com.plamen.audit.process-custody.v2.plist",
    ),
    ("native_builder_header", "native/posix/plamen_native_builder_v2.h"),
    ("native_builder", "native/posix/plamen_native_builder_v2.c"),
    ("posix_guest_bootstrap", "native/posix/plamen_guest_bootstrap.py"),
    ("native_installer_header", "native/posix/plamen_native_installer_v2.h"),
    ("native_installer", "native/posix/plamen_native_installer_v2.c"),
    ("source_install_dispatch", "scripts/posix_native_install_dispatch.py"),
    (
        "cold_install_transaction",
        "scripts/posix_native_install_transaction.py",
    ),
    (
        "cold_install_publication",
        "scripts/posix_native_install_publication.py",
    ),
    ("cold_install_effects", "scripts/posix_native_install_effects.py"),
    (
        "managed_evm_setup_transaction",
        "scripts/posix_managed_evm_setup_transaction.py",
    ),
    (
        "native_managed_evm_setup_effects",
        "scripts/native_managed_evm_setup_effects.py",
    ),
    ("package_front", "plamen.py"),
    (
        "runtime_source_projection",
        "scripts/runtime_source_projection.py",
    ),
    (
        "runtime_source_projection_manifest",
        "verification_policy/runtime_source_projection.v1.json",
    ),
    ("native_runtime_bindings", "scripts/native_runtime_bindings.py"),
    (
        "native_runtime_policy_artifacts",
        "scripts/runtime_policy_artifacts.py",
    ),
    ("native_elf_loader_closure", "scripts/elf_loader_closure.py"),
    (
        "native_runtime_image_materializer",
        "scripts/runtime_image_materializer.py",
    ),
    (
        "opengrep_release_policy",
        "scripts/opengrep_release_policy.py",
    ),
    (
        "medusa_release_policy",
        "scripts/medusa_release_policy.py",
    ),
    (
        "native_static_acquisition_policies",
        "scripts/native_static_acquisition_policies.py",
    ),
    (
        "native_operation4_acquisition_validation",
        "scripts/native_operation4_acquisition_validation.py",
    ),
    (
        "native_evm_static_acquisition_assets",
        "scripts/native_evm_static_acquisition_assets.py",
    ),
    (
        "native_fixed_role_acquisition",
        "scripts/native_fixed_role_acquisition.py",
    ),
    ("runtime_role10_acquisition", "scripts/runtime_role10_acquisition.py"),
    (
        "runtime_role10_base_rootfs_acquisition_policy",
        "verification_policy/runtime_role10_base_rootfs_acquisition.v1.json",
    ),
    (
        "runtime_role10_base_rootfs_source_manifest",
        "verification_policy/runtime_role10_base_rootfs_source_manifest.v1.json",
    ),
    (
        "runtime_role10_debian_package_state_acquisition_policy",
        "verification_policy/runtime_role10_debian_package_state_acquisition.v1.json",
    ),
    (
        "runtime_role10_debian_package_state_source_manifest",
        "verification_policy/runtime_role10_debian_package_state_source_manifest.v1.json",
    ),
    (
        "runtime_role10_plamen_guest_acquisition_policy",
        "verification_policy/runtime_role10_plamen_guest_acquisition.v1.json",
    ),
    (
        "runtime_role10_cpython_acquisition_policy",
        "verification_policy/runtime_role10_cpython_acquisition.v1.json",
    ),
    (
        "runtime_role10_cpython_source_manifest",
        "verification_policy/runtime_role10_cpython_source_manifest.v1.json",
    ),
    (
        "runtime_role10_plamen_package_acquisition_policy",
        "verification_policy/runtime_role10_plamen_package_acquisition.v1.json",
    ),
    ("native_backend_acquisition", "scripts/backend_acquisition.py"),
    ("native_oci_image_lock", "scripts/oci_image_lock.py"),
    (
        "native_runtime_bindings_policy",
        "verification_policy/native_runtime_bindings.v2.json",
    ),
    (
        "apple_container_image_generation_policy",
        "verification_policy/apple_container_runtime_image_generation.v1.json",
    ),
    (
        "opengrep_acquisition_policy",
        "verification_policy/opengrep_acquisition.v1.json",
    ),
    (
        "opengrep_runtime_source_manifest",
        "verification_policy/opengrep_runtime_source_manifest.v1.json",
    ),
    (
        "native_backend_latest_acquisition_policy",
        "verification_policy/native_backend_acquisition.v2.json",
    ),
    (
        "medusa_acquisition_policy",
        "verification_policy/medusa_acquisition.v1.json",
    ),
    (
        "medusa_acquisition_receipt",
        "verification_policy/medusa_acquisition_receipt.v1.json",
    ),
    (
        "medusa_runtime_source_manifest",
        "verification_policy/medusa_runtime_source_manifest.v1.json",
    ),
    (
        "solc_amd64_acquisition_policy",
        "verification_policy/solc_amd64_acquisition.v1.json",
    ),
    (
        "solc_amd64_acquisition_receipt",
        "verification_policy/solc_amd64_acquisition_receipt.v1.json",
    ),
    (
        "solc_amd64_runtime_source_manifest",
        "verification_policy/solc_amd64_runtime_source_manifest.v1.json",
    ),
    (
        "foundry_acquisition_policy",
        "verification_policy/foundry_acquisition.v1.json",
    ),
    (
        "foundry_acquisition_receipt",
        "verification_policy/foundry_acquisition_receipt.v1.json",
    ),
    (
        "foundry_runtime_source_manifest",
        "verification_policy/foundry_runtime_source_manifest.v1.json",
    ),
    (
        "amd64_compat_acquisition_policy",
        "verification_policy/amd64_compat_acquisition.v1.json",
    ),
    (
        "amd64_compat_acquisition_receipt",
        "verification_policy/amd64_compat_acquisition_receipt.v1.json",
    ),
    (
        "amd64_compat_runtime_source_manifest",
        "verification_policy/amd64_compat_runtime_source_manifest.v1.json",
    ),
)
# The final source freeze is a separately reviewed, committed canonical
# manifest.  Keeping hashes in this Python file created a self-referential and
# routinely stale partial allowlist: changing the builder could silently leave
# every other old hash looking authoritative.  The candidate command below
# observes this exact fixed roster, including this builder, but never grants
# build or installation authority.
PRODUCTION_SOURCE_FREEZE_SCHEMA = "plamen.native-production-source-freeze.v2"
PRODUCTION_SOURCE_FREEZE_MANIFEST = (
    REPOSITORY_ROOT / "native" / "darwin"
    / "native-production-source-freeze-v2.json"
)
PRODUCTION_SOURCE_FREEZE_MAX_BYTES = 256 * 1024
PRODUCTION_SOURCE_MEMBER_MAX_BYTES = 16 * 1024 * 1024
PRODUCTION_PACKAGE_SNAPSHOT_MAX_ROWS = 32_768
PRODUCTION_PACKAGE_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024 * 1024
PRODUCTION_PACKAGE_SNAPSHOT_MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
_OPERATION4_ROLE_COUNT = 11
_OPERATION4_POLICY_SCHEMAS = (
    "plamen.debian-runtime-acquisition-receipt.v1",
    "plamen.debian-runtime-acquisition-receipt.v1",
    "plamen.plamen-source-projection-acquisition-receipt.v1",
    "plamen.cpython-runtime-acquisition-receipt.v1",
    "plamen.plamen-source-projection-acquisition-receipt.v1",
    "plamen.native-backend-latest-acquisition-receipt.v1",
    "plamen.native-backend-latest-acquisition-receipt.v1",
    "plamen.foundry-acquisition-receipt.v1",
    "plamen.medusa-acquisition-receipt.v1",
    "plamen.solc-amd64-acquisition-receipt.v1",
    "plamen.amd64-compat-acquisition-receipt.v1",
)
_OPERATION4_IDENTITY_MODES = (1, 1, 3, 1, 3, 2, 2, 1, 1, 1, 1)
_OPERATION4_RECEIPT_VALIDATORS = (1, 1, 2, 3, 2, 4, 4, 5, 6, 7, 8)
# Only the standalone signed source-bootstrap coordinator may embed the strong
# operation-4 policy.  In particular, role 2 contains the CPython extension;
# embedding a policy that itself binds role 2's payload hash in that extension
# would create an impossible payload -> extension -> policy -> payload fixed
# point.  The extension retains only the fail-closed/readmission code surface;
# the installed coordinator receipt supplies the independently signed roster.
PRODUCTION_OPERATION4_POLICY_CONSUMERS = frozenset({
    "retained-source-bootstrap-coordinator",
})
# These facts are transaction products, not source-install prerequisites.  A
# cold install must be able to create them, but it may do so only when every
# other readiness blocker has cleared and the exact source/projection freeze
# has been replayed again at the transaction boundary.
PRODUCTION_COLD_INSTALL_OUTPUT_BLOCKERS = frozenset({
    "CODEX_COMMITTED_PACKAGE_TRANSACTION_ABSENT",
    "EVM_SIGNED_TOOL_AUTHORITY_PRODUCER_ABSENT",
    "INSTALLED_CLOSURE_CODE_REQUIREMENT_RECEIPT_ABSENT",
    "INTRINSIC_GENERATION_ARTIFACT_ROSTER_UNBUILT",
    "MULTI_ARTIFACT_RETAINED_INSTALL_HANDOFF_ABSENT",
    "PRODUCTION_CODE_SIGNATURE_ROSTER_UNOBSERVED",
    "PRODUCTION_COMPILE_LINK_CLOSURE_UNOBSERVED",
    "PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",
    "RUNTIME_PACKAGE_MANIFEST_UNBUILT",
    "SOURCE_INSTALL_COORDINATOR_TRANSACTION_ABSENT",
})
CODEX_COMMITTED_RECEIPT_SCHEMA = "plamen.codex_install.v2"
CODEX_COMMITTED_RECEIPT_MAX_BYTES = 64 * 1024 * 1024
CODEX_COMMITTED_RECEIPT_FIELDS = frozenset({
    "schema", "transaction_id", "state", "source_count", "runtime_count",
    "adapter_count", "source_manifest_sha256", "runtime_manifest_sha256",
    "adapter_manifest_sha256", "source_root", "plamen_root", "codex_root",
    "lock_identity", "owner", "transaction_root", "stage_root",
    "backup_root", "inverse_path", "journal_path", "rows", "journal",
    "created_junction", "last_transition_ns", "inverse_sha256",
    "junction_identity", "terminal_verification", "terminal_evidence",
})
CODEX_COMMITTED_ROW_FIELDS = frozenset({
    "source_path", "install_kind", "destination_root", "destination_path",
    "destination_key", "size", "sha256", "destination", "stage",
    "terminal_authority",
})
CODEX_COMMITTED_JOURNAL_FIELDS = frozenset({
    "index", "destination", "sha256", "terminal_authority",
})
CODEX_COMMITTED_FILE_AUTHORITY_FIELDS = frozenset({
    "kind", "device", "inode", "mode", "links", "size",
    "attributes", "reparse_tag", "name", "sha256", "streams",
})
CODEX_INSTALL_TERMINAL_FIELD_SHAPES = (
    frozenset({
        "verified_count", "verified_manifest_sha256", "completed_ns",
    }),
    frozenset({
        "verified_count", "verified_manifest_sha256", "completed_ns",
        "projection_public_key",
    }),
    frozenset({
        "verified_count", "verified_manifest_sha256", "completed_ns",
        "projection_public_key", "projection_lock_public_key",
    }),
    frozenset({
        "verified_count", "verified_manifest_sha256", "completed_ns",
        "projection_public_key", "projection_lock_public_key",
        "projection_lock_authority_sha256",
    }),
)
CODEX_TERMINAL_EVIDENCE_FILENAMES = (
    "precommit.json", "transaction.json", "smoke.json", "recovery.json",
    "broker.json", "process.json", "environment.json", "sentinel.json",
    "manifest.json", "folder-seal.json", "terminal-last.json",
)
# Compatibility diagnostic for tests that previously inspected the partial
# in-module pin map.  It is intentionally and permanently empty; only the
# external canonical manifest can freeze the complete denominator.
PRODUCTION_FROZEN_SOURCE_SHA256 = MappingProxyType({})
PRODUCTION_DARWIN_FRAMEWORK_ROSTER = (
    "CoreFoundation.framework",
    "Security.framework",
    "libSystem",
)
PRODUCTION_DARWIN_SIGNING_IDENTIFIERS = MappingProxyType({
    "launcher": "com.plamen.audit.launcher.v2",
    "service": "com.plamen.audit.broker.v2",
    "extension": "com.plamen.audit.native-supervisor.v2",
    "installer": "com.plamen.audit.installer.v2",
    "source_bootstrap": "com.plamen.audit.source-bootstrap.v1",
})
PRODUCTION_DARWIN_SOURCE_INSTALL_TOOLS = MappingProxyType({
    "compiler": "/usr/bin/clang",
    "signer": "/usr/bin/codesign",
    "plist_validator": "/usr/bin/plutil",
    "service_manager": "/bin/launchctl",
    "symbol_inspector": "/usr/bin/nm",
})
PRODUCTION_DARWIN_LINK_ROSTER = (
    {
        "artifact": "_plamen_native_supervisor{EXT_SUFFIX}",
        "compile_flags": (
            "-std=c11", "-fPIC", "-fvisibility=hidden",
            "-Wall", "-Wextra", "-Werror", "-fblocks",
            "-DPLAMEN_NATIVE_INSTALLED_BACKEND_GENERATION_V1=1",
        ),
        "kind": "cpython-extension",
        "flags": (
            "-bundle", "-undefined", "dynamic_lookup",
            "-framework", "CoreFoundation", "-framework", "Security",
        ),
        "init_symbol": "PyInit__plamen_native_supervisor",
        "source_roles": (
            "cpython_extension", "broker_protocol", "broker_protocol_header",
            "darwin_install_receipt", "darwin_install_receipt_header",
            "darwin_source_bootstrap_coordinator",
            "darwin_source_bootstrap_coordinator_header",
            "darwin_operation4_helper", "darwin_operation4_helper_header",
            "shared_broker_abi",
        ),
    },
    {
        "artifact": "plamen-audit-broker-v2",
        "compile_flags": (
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
        ),
        "kind": "launchd-xpc-service",
        "flags": ("-framework", "CoreFoundation", "-framework", "Security"),
        "init_symbol": None,
        "source_roles": (
            "darwin_service", "darwin_service_store",
            "darwin_service_store_header", "darwin_process",
            "darwin_process_header", "darwin_process_custodian",
            "darwin_process_custodian_header",
            "darwin_process_custody_daemon",
            "darwin_process_custody_daemon_header",
            "darwin_process_custody_client",
            "darwin_process_custody_client_header", "darwin_apple_container",
            "darwin_apple_container_header", "darwin_apple_lifecycle",
            "darwin_apple_lifecycle_header", "darwin_fuzz_campaign",
            "darwin_fuzz_campaign_header", "darwin_fuzz_service",
            "darwin_tool_custody",
            "darwin_tool_custody_header", "darwin_effects",
            "darwin_effects_header", "darwin_artifact_export",
            "darwin_artifact_export_header", "darwin_specialized_request",
            "darwin_specialized_request_header",
            "darwin_specialized_runtime_authority",
            "darwin_specialized_runtime_authority_header",
            "darwin_specialized_runtime_effects_handoff",
            "darwin_specialized_runtime_effects_handoff_header",
            "darwin_specialized_effect_store",
            "darwin_specialized_effect_store_header",
            "darwin_specialized_apple_effect_execution",
            "darwin_specialized_apple_effect_execution_header",
            "darwin_specialized_output_census",
            "darwin_specialized_output_census_header",
            "darwin_specialized_output_receipt",
            "darwin_specialized_output_receipt_header",
            "darwin_image_member_receipt",
            "darwin_image_member_receipt_header", "darwin_workspace_effects",
            "darwin_workspace_effects_header", "darwin_operations",
            "darwin_operations_header", "darwin_install_receipt",
            "darwin_install_receipt_header", "broker_protocol",
            "broker_protocol_header", "native_builder",
            "native_builder_header",
            "shared_broker_abi",
        ),
    },
    {
        "artifact": "plamen-native-launcher",
        "compile_flags": (
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
        ),
        "kind": "fixed-native-entrypoint",
        "flags": ("-framework", "CoreFoundation", "-framework", "Security"),
        "init_symbol": None,
        "source_roles": (
            "darwin_launcher", "darwin_install_receipt",
            "darwin_install_receipt_header", "broker_protocol",
            "broker_protocol_header",
            "darwin_deployment_receipt",
            "darwin_deployment_receipt_header",
            "shared_broker_abi",
        ),
    },
    {
        "artifact": "plamen-native-installer-v2",
        "compile_flags": (
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-fblocks",
            "-DPLAMEN_NATIVE_INSTALL_COORDINATOR_V2_MAIN",
        ),
        "kind": "retained-install-coordinator",
        "flags": ("-framework", "CoreFoundation", "-framework", "Security"),
        "init_symbol": None,
        "source_roles": (
            "darwin_install_coordinator",
            "darwin_install_coordinator_header",
            "darwin_code_identity", "darwin_code_identity_header",
            "darwin_deployment_receipt",
            "darwin_deployment_receipt_header",
            "darwin_launchd_installer",
            "darwin_launchd_installer_header",
            "darwin_launchd_readiness",
            "darwin_launchd_readiness_header",
            "darwin_install_receipt",
            "darwin_install_receipt_header",
            "darwin_image_member_receipt",
            "darwin_image_member_receipt_header",
            "native_installer", "native_installer_header",
            "native_builder", "native_builder_header",
            "darwin_source_bootstrap_coordinator",
            "darwin_source_bootstrap_coordinator_header",
        ),
    },
    {
        "artifact": "plamen-native-source-bootstrap-coordinator-v1",
        "compile_flags": (
            "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-DPLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_MAIN",
        ),
        "kind": "retained-source-bootstrap-coordinator",
        "flags": ("-framework", "Security", "-lproc"),
        "init_symbol": None,
        "source_roles": (
            "darwin_source_bootstrap_coordinator",
            "darwin_source_bootstrap_coordinator_header",
            "darwin_operation4_helper",
            "darwin_operation4_helper_header",
            "darwin_backend_receipt_signer",
            "darwin_backend_receipt_signer_header",
            "darwin_backend_receipt_signer_swift",
            "darwin_evm_static_acquisition",
            "darwin_evm_static_acquisition_header",
            "darwin_evm_static_acquisition_swift",
            "darwin_evm_static_assets",
            "darwin_fixed_role_acquisition",
            "darwin_fixed_role_acquisition_header",
        ),
    },
)
PRODUCTION_DARWIN_GENERATION_INSTALL_ROSTER = (
    "bin/python3.12",
    "bin/plamen-native-launcher",
    "lib/plamen/plamen-audit-broker-v2",
    "lib/plamen/_plamen_native_supervisor{EXT_SUFFIX}",
    "share/plamen/plamen_broker_v2.h",
    "share/plamen/native-supervisor-schema-v2.json",
    "Library/LaunchAgents/com.plamen.audit.broker.v2.plist",
    "Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist",
    "lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
    "share/plamen/runtime-package-manifest-v2.bin",
    "libexec/plamen-native-installer-v2",
    "libexec/plamen-native-source-bootstrap-coordinator-v1",
)
PRODUCTION_DARWIN_INSTALL_ROOT_DEPLOYMENT_ROSTER = (
    "bin/plamen-native-launcher",
    "generations/{generation_id}/libexec/plamen-native-installer-v2",
    (
        "generations/{generation_id}/libexec/"
        "plamen-native-source-bootstrap-coordinator-v1"
    ),
    "share/plamen/native-install-receipt-v2.bin",
    "share/plamen/native-deployment-receipt-v2.bin",
)
PRODUCTION_DARWIN_INSTALL_ROSTER = (
    *PRODUCTION_DARWIN_GENERATION_INSTALL_ROSTER,
    *PRODUCTION_DARWIN_INSTALL_ROOT_DEPLOYMENT_ROSTER,
)
PRODUCTION_DARWIN_PUBLIC_TOPOLOGY = MappingProxyType({
    "native_home_authority": "getpwuid_r(getuid()).pw_dir",
    "install_root": "{pw_dir}/.local/share/plamen",
    "public_command": "{pw_dir}/.local/bin/plamen",
    "public_command_role": "ORDINARY_V3_FRONT_SHIM_NOT_AUTHORITY",
    "installed_source": "{pw_dir}/.plamen",
    "managed_python": (
        "{pw_dir}/.local/share/plamen/runtime/py312/bin/python"
    ),
    "front_script": "{pw_dir}/.plamen/plamen.py",
    "internal_launcher": (
        "{pw_dir}/.local/share/plamen/generations/{generation_id}/"
        "bin/plamen-native-launcher"
    ),
    "stable_internal_launcher": (
        "{pw_dir}/.local/share/plamen/bin/plamen-native-launcher"
    ),
    "stable_internal_launcher_publication": (
        "ATOMIC_HARDLINK_AFTER_AUTHENTICATED_SERVICE_READINESS"
    ),
    "native_child_argv": (
        "{generation}/bin/python3.12", "-I", "-B",
        "{generation}/lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
    ),
    "outer_entrypoint_request_source": (
        "INITIAL_AUTHORITY.request_projection"
    ),
    "native_transition": (
        "start-config-or-resume -> internal-launcher exactly once -> "
        "fixed-generation-python-and-driver"
    ),
    "environment_recursion_marker_allowed": False,
})
PRODUCTION_GENERATION_ID_SCHEMA = (
    "plamen.native-supervisor.intrinsic-generation.v2"
)
PRODUCTION_GENERATION_INTRINSIC_ROLES = (
    "launcher",
    "service",
    "extension",
    "shared_abi",
    "schema",
    "python",
    "outer_entrypoint",
    "runtime_manifest",
    "install_coordinator",
    "source_bootstrap_coordinator",
)
PRODUCTION_GENERATION_DEPLOYMENT_ROLES = (
    "launchd_plist",
    "install_receipt",
)
DARWIN_INSTALL_RECEIPT_V2_SIZE = 16384
DARWIN_INSTALL_RECEIPT_V2_HASHED_SIZE = 16352
DARWIN_CODEX_PROFILE_V2_MAGIC = b"PLMBPF2\0"
DARWIN_CODEX_PROFILE_V2_VERSION = 2
DARWIN_CODEX_PROFILE_V2_HEADER_SIZE = 256
DARWIN_CODEX_PROFILE_V2_SIZE = 2048
DARWIN_CODEX_PROFILE_V2_HASHED_SIZE = 2016
DARWIN_CODEX_PROFILE_V2_PATH = "profiles/codex-v2.bin"
DARWIN_CODEX_PROFILE_V2_PROVIDER_IDENTIFIER = "com.apple.container.cli"
DARWIN_CODEX_PROFILE_V2_PROVIDER_TEAM = "UPBK2H6LZM"
DARWIN_CODEX_PROFILE_V2_BACKEND_IDENTIFIER = "codex"
DARWIN_CODEX_PROFILE_V2_BACKEND_TEAM = "2DC432GLL2"
DARWIN_CODEX_PROFILE_V2_BACKEND_SELECTOR = "codex"
DARWIN_CODEX_PROFILE_V2_PROVIDER_SELECTOR = "apple-container-v2"
DARWIN_CLAUDE_PROFILE_V2_PATH = "profiles/claude-v2.bin"
DARWIN_CLAUDE_PROFILE_V2_BACKEND_IDENTIFIER = "com.anthropic.claude-code"
DARWIN_CLAUDE_PROFILE_V2_BACKEND_TEAM = "Q6L2SF6YDW"
DARWIN_CLAUDE_PROFILE_V2_BACKEND_SELECTOR = "claude"
NATIVE_BACKEND_ACQUISITION_POLICY_V2 = (
    REPOSITORY_ROOT / "verification_policy"
    / "native_backend_acquisition.v2.json"
)
DARWIN_BACKEND_PROFILE_V2_IDENTITIES = MappingProxyType({
    "codex": MappingProxyType({
        "backend_identifier": DARWIN_CODEX_PROFILE_V2_BACKEND_IDENTIFIER,
        "backend_team": DARWIN_CODEX_PROFILE_V2_BACKEND_TEAM,
        "runtime_path": DARWIN_CODEX_PROFILE_V2_PATH,
    }),
    "claude": MappingProxyType({
        "backend_identifier": DARWIN_CLAUDE_PROFILE_V2_BACKEND_IDENTIFIER,
        "backend_team": DARWIN_CLAUDE_PROFILE_V2_BACKEND_TEAM,
        "runtime_path": DARWIN_CLAUDE_PROFILE_V2_PATH,
    }),
})
DARWIN_INSTALL_RECEIPT_V2_MEMBERS = (
    (
        "launcher", 1, "bin/plamen-native-launcher", 0o500,
        "com.plamen.audit.launcher.v2", True,
    ),
    (
        "service", 2, "lib/plamen/plamen-audit-broker-v2", 0o500,
        "com.plamen.audit.broker.v2", True,
    ),
    (
        "extension", 3,
        "lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so", 0o400,
        "com.plamen.audit.native-supervisor.v2", True,
    ),
    ("shared_abi", 4, "share/plamen/plamen_broker_v2.h", 0o400, "", False),
    (
        "schema", 5, "share/plamen/native-supervisor-schema-v2.json", 0o400,
        "", False,
    ),
    ("python", 6, "bin/python3.12", 0o500, None, True),
    (
        "outer_entrypoint", 7,
        "lib/plamen/runtime/scripts/posix_audit_entrypoint.py", 0o400,
        "", False,
    ),
    (
        "runtime_manifest", 8,
        "share/plamen/runtime-package-manifest-v2.bin", 0o400, "", False,
    ),
    (
        "install_coordinator", 9,
        "libexec/plamen-native-installer-v2", 0o500,
        "com.plamen.audit.installer.v2", True,
    ),
    (
        "source_bootstrap_coordinator", 10,
        "libexec/plamen-native-source-bootstrap-coordinator-v1", 0o500,
        "com.plamen.audit.source-bootstrap.v1", True,
    ),
)
RUNTIME_PACKAGE_MANIFEST_V2_MAGIC = b"PLMRPM2\0"
RUNTIME_PACKAGE_MANIFEST_V2_VERSION = 2
RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE = 256
RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE = 2048
RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE = 640
RUNTIME_PACKAGE_MANIFEST_V2_TRAILER_SIZE = 32
RUNTIME_PACKAGE_MANIFEST_V2_ROOT = "lib/plamen/runtime"
RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES = 8192
RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES = 512
RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH = 64
RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES = 64 * 1024 * 1024
RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES = 512 * 1024 * 1024
RUNTIME_PACKAGE_MANIFEST_V2_DIRECTORY = 1
RUNTIME_PACKAGE_MANIFEST_V2_FILE = 2
RUNTIME_PACKAGE_MANIFEST_V2_FLAGS = 1
RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES = (
    "profiles/claude-v2.bin",
    "profiles/codex-v2.bin",
    "scripts/plamen_driver.py",
    "scripts/posix_audit_entrypoint.py",
    "scripts/posix_native_authority_adapter.py",
    "scripts/posix_specialized_tool_worker.py",
    "scripts/report_output_routing.py",
    "scripts/native_managed_evm_driver_preflight.py",
    "scripts/native_managed_evm_setup_effects.py",
    "scripts/posix_managed_evm_setup_transaction.py",
)
RUNTIME_PACKAGE_MANIFEST_V2_TARGET_ARCHES = MappingProxyType({
    "arm64": 1,
    "amd64": 2,
})
RUNTIME_PACKAGE_MANIFEST_V2_INIT_REFERENCE = "/usr/local/libexec/plamen-guest"
RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_FIELDS = (
    "oci_image_reference",
    "oci_init_reference",
)
RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS = (
    "oci_index_digest",
    "image_manifest_digest",
    "oci_config_digest",
    "image_closure_sha256",
    "apple_container_configuration_sha256",
    "seccomp_profile_sha256",
    "baked_toolchain_closure_sha256",
    "oci_lock_sha256",
    "materialization_receipt_sha256",
    "rootfs_archive_sha256",
    "rootfs_diff_id_sha256",
    "closure_census_sha256",
    "sbom_sha256",
    "provenance_sha256",
)
RUNTIME_PACKAGE_MANIFEST_V2_BINDING_MAGIC = b"PLMRPB2\0"
RUNTIME_PACKAGE_MANIFEST_V2_BINDING_FLAGS = 1
RUNTIME_PACKAGE_MANIFEST_V2_FIELD_ORDER_KAT = hashlib.sha256(
    b"plamen.runtime-package-binding.field-order.v2\0"
    + b"\0".join(
        item.encode("ascii")
        for item in (
            "target_arch",
            *RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_FIELDS,
            *RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS,
        )
    )
).digest()
# Reserved denominator for the Linux release slice.  The admission and
# lifecycle/process-custody source closure is named below, while the executable
# intrinsic roster remains deliberately unbuilt until live rootless receipt and
# cleanup gates are validated.  Naming both prevents an installer from
# treating either class as unbound optional files.
PRODUCTION_LINUX_RESERVED_INTRINSIC_ROSTER = (
    ("systemd_user_unit", "share/systemd/user/plamen-audit-broker-v2.service", 0o400),
    ("guest_bootstrap", "usr/local/libexec/plamen-guest", 0o500),
    ("broker", "libexec/plamen-audit-broker-v2", 0o500),
)
PRODUCTION_LINUX_ADMISSION_SOURCE_ROSTER = (
    "native/linux/plamen_broker_v2_linux.h",
    "native/linux/plamen_broker_v2_linux_process.c",
    "native/linux/plamen_linux_install_receipt_v2.h",
    "native/linux/plamen_linux_install_receipt_v2.c",
    "native/linux/plamen_broker_v2_podman_admission.h",
    "native/linux/plamen_broker_v2_podman_admission.c",
    "native/linux/plamen_broker_v2_podman_lifecycle.h",
    "native/linux/plamen_broker_v2_podman_lifecycle.c",
)
PRODUCTION_LINUX_NATIVE_ENDPOINTS = MappingProxyType({
    "outer_host": "/run/user/{native_uid}/plamen/broker-v2.sock",
    "guest": "/run/plamen/broker-v2.sock",
    "environment_token_allowed": False,
})
PRODUCTION_LINUX_INSTALL_RECEIPT_V2 = MappingProxyType({
    "schema": "plamen.linux-install-receipt.v2",
    "magic": "PLNLIR2\\0",
    "version": 2,
    "byte_count": 8192,
    "hashed_byte_count": 8160,
    "receipt_fd": 198,
    "install_root_fd": 199,
    "scopes": {
        "outer_user": {
            "socket": "/run/user/{native_uid}/plamen/broker-v2.sock",
            "uid": "exact-native-uid-nonzero",
        },
        "guest_root": {
            "socket": "/run/plamen/broker-v2.sock",
            "uid": 0,
            "gid": 0,
        },
    },
    "member_roles": (
        "broker", "extension", "interpreter", "service_bootstrap",
    ),
    "member_bindings": (
        "safe-root-relative-path", "sha256", "byte-count",
        "device-inode-mode-uid-gid-link-count", "broker-v2-fd-identity",
        "elf-pt-interp-identity", "ordered-dt-needed-closure",
    ),
    "authority_bindings": (
        "immutable-install-root-fd-identity", "generation-id",
        "signed-install-provenance", "installed-closure",
        "protocol-schema", "runtime-package-manifest",
        "native-deployment-receipt", "receipt-producer-identity",
        "receipt-self-digest", "derived-session-binding",
    ),
    "open_policy": (
        "retained-root-openat2-resolve-beneath-no-symlinks-no-magiclinks-"
        "no-xdev"
    ),
    "same_uid_sufficient": False,
    "live_receipt_observed": False,
})
PRODUCTION_LINUX_GUEST_RUNTIME = MappingProxyType({
    "source_mount": "/opt/plamen",
    "source_mount_mode": "READ_ONLY_AUTHENTICATED_V3_ARCHIVE",
    "driver": "/opt/plamen/scripts/plamen_driver.py",
    "guest_bootstrap": "/usr/local/libexec/plamen-guest",
    "interpreter": "/usr/bin/python3",
    "interpreter_argv": ("-B", "/opt/plamen/scripts/plamen_driver.py"),
    "extension": (
        "/usr/local/lib/plamen/native/cpython-312/"
        "_plamen_native_supervisor.so"
    ),
    "native_receipt": (
        "/usr/local/share/plamen/native-install-receipt-v2.bin"
    ),
    "tool_root": "/usr/local/lib/plamen",
    "solc": "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
    "forge": "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
    "foundry_offline_environment": "FOUNDRY_OFFLINE=true",
    "forge_required_flags": (
        "--offline", "--use",
        "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
    ),
    "environment_discovery_allowed": False,
})
_SYSCONFIG_KEYS = (
    "ABIFLAGS", "AR", "ARFLAGS", "CC", "CCSHARED", "CFLAGS",
    "CONFIG_ARGS", "EXT_SUFFIX", "LDFLAGS", "LDSHARED", "LIBS",
    "MACOSX_DEPLOYMENT_TARGET", "MULTIARCH", "Py_DEBUG", "SDKROOT",
    "SOABI", "SYSLIBS",
)
_CLOSED_ENV = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._+-]{0,254}\Z")
# CPython 3.12's ``stat`` module does not expose Darwin's SF_RESTRICTED even
# though ``st_flags`` reports it.  The value is the Darwin stat ABI constant;
# production readiness independently binds the selected SDK and toolchain.
_DARWIN_SF_RESTRICTED = 0x00080000 if sys.platform == "darwin" else 0


class BuildError(RuntimeError):
    """A fail-closed native build validation error."""


def _production_host_platform_key() -> str:
    """Return the exact native release slice before touching install inputs."""

    machine = os.uname().machine
    if sys.platform == "darwin" and machine == "arm64":
        return "darwin-arm64"
    if sys.platform == "linux" and machine in {"x86_64", "amd64"}:
        return "linux-x86_64"
    if sys.platform == "linux" and machine in {"aarch64", "arm64"}:
        return "linux-arm64"
    raise BuildError(
        "NATIVE_RELEASE_SLICE_UNSUPPORTED: supported production hosts are "
        "Darwin arm64 and Linux x86_64/aarch64"
    )


def _load_linux_install_authority_module() -> ModuleType:
    """Descriptor-retain and execute the bounded Linux policy module.

    The loaded Python result is diagnostic policy only.  Its own production
    contract retains signed-provenance and native-effect blockers, so this
    loader cannot mint install authority.  A source freeze later binds these
    exact bytes before any Linux builder may consume the policy.
    """

    descriptor = -1
    module_name = "_plamen_linux_native_install_authority"
    previous = sys.modules.get(module_name)
    try:
        descriptor, resolved, identity = _open_retained_regular(
            LINUX_INSTALL_AUTHORITY_SOURCE,
            "Linux native install authority",
        )
        if resolved != LINUX_INSTALL_AUTHORITY_SOURCE:
            raise BuildError("LINUX_INSTALL_AUTHORITY_ALIASED")
        raw = _read_fd(
            descriptor, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
            "Linux native install authority",
        )
        if (
            identity["size"] != len(raw)
            or identity["sha256"] != hashlib.sha256(raw).hexdigest()
            or not _same_stat(
                os.fstat(descriptor),
                os.stat(LINUX_INSTALL_AUTHORITY_SOURCE, follow_symlinks=False),
            )
        ):
            raise BuildError("LINUX_INSTALL_AUTHORITY_DRIFTED")
        module = ModuleType(module_name)
        module.__file__ = str(LINUX_INSTALL_AUTHORITY_SOURCE)
        module.__package__ = None
        module.__cached__ = None
        sys.modules[module_name] = module
        exec(
            compile(
                raw, str(LINUX_INSTALL_AUTHORITY_SOURCE), "exec",
                dont_inherit=True,
            ),
            module.__dict__, module.__dict__,
        )
        return module
    except BuildError:
        raise
    except BaseException as exc:
        raise BuildError(
            "LINUX_INSTALL_AUTHORITY_UNAVAILABLE: "
            + f"{type(exc).__name__}:{exc}"
        ) from None
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
        if descriptor >= 0:
            os.close(descriptor)


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    )


def _strict_json_object(raw: bytes, label: str) -> dict[str, Any]:
    """Decode one bounded JSON object without duplicate-key ambiguity."""

    if type(raw) is not bytes:
        raise BuildError(f"{label} bytes are not exact")

    def reject_constant(_value: str) -> Any:
        raise ValueError("non-finite number")

    def pairs(pairs_value: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs_value:
            if type(key) is not str or key in result:
                raise ValueError("duplicate or non-string object key")
            result[key] = value
        return result

    try:
        decoded = json.loads(
            raw.decode("ascii", "strict"), object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise BuildError(f"{label} is not strict canonical JSON") from exc
    if type(decoded) is not dict:
        raise BuildError(f"{label} is not one JSON object")
    return decoded


def _production_source_definition_sha256() -> str:
    rows = [
        {"role": role, "path": relative}
        for role, relative in PRODUCTION_DARWIN_SOURCE_ROSTER
    ]
    if (
        len({row["role"] for row in rows}) != len(rows)
        or len({row["path"] for row in rows}) != len(rows)
    ):
        raise BuildError("production source roster contains duplicate authority")
    return hashlib.sha256(
        b"PLAMEN-NATIVE-SOURCE-ROSTER-DEFINITION-V2\0"
        + _canonical_json_bytes(rows)
    ).hexdigest()


def _production_source_rows_sha256(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        b"PLAMEN-NATIVE-SOURCE-ROSTER-CONTENT-V2\0"
        + _canonical_json_bytes(rows)
    ).hexdigest()


def _observe_production_source_roster() -> tuple[
    list[dict[str, Any]], dict[str, bytes], list[str]
]:
    """Descriptor-observe every fixed source member, without accepting it."""

    rows: list[dict[str, Any]] = []
    content: dict[str, bytes] = {}
    blockers: list[str] = []
    with ExitStack() as resources:
        for role, relative in PRODUCTION_DARWIN_SOURCE_ROSTER:
            path = REPOSITORY_ROOT / relative
            try:
                descriptor, resolved, identity = _open_retained_regular(
                    path, f"production {role}"
                )
            except (BuildError, OSError):
                rows.append({"path": relative, "role": role, "status": "MISSING"})
                blockers.append(f"SOURCE_MISSING:{role}:{relative}")
                continue
            resources.callback(os.close, descriptor)
            if resolved != path:
                rows.append({"path": relative, "role": role, "status": "ALIASED"})
                blockers.append(f"SOURCE_ALIASED:{role}:{relative}")
                continue
            if identity["size"] > PRODUCTION_SOURCE_MEMBER_MAX_BYTES:
                rows.append({"path": relative, "role": role, "status": "INVALID"})
                blockers.append(f"SOURCE_INVALID:{role}:{relative}")
                continue
            try:
                raw = _read_fd(
                    descriptor, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                    f"production {role}",
                )
            except BuildError:
                rows.append({"path": relative, "role": role, "status": "INVALID"})
                blockers.append(f"SOURCE_INVALID:{role}:{relative}")
                continue
            content[role] = raw
            rows.append({
                "path": relative,
                "role": role,
                "sha256": identity["sha256"],
                "size": identity["size"],
                "status": "OBSERVED_DIAGNOSTIC_ONLY",
            })
    return rows, content, blockers


def render_production_source_freeze_candidate() -> bytes:
    """Render the review candidate for the final, separately committed freeze.

    Calling this function is observation only.  In particular, it neither
    writes the fixed manifest path nor enables a production build.  The
    candidate must be generated after all source owners stop editing, reviewed,
    committed as one package member, and then revalidated by readiness.
    """

    observed, _content, blockers = _observe_production_source_roster()
    if blockers or any(row.get("status") != "OBSERVED_DIAGNOSTIC_ONLY"
                       for row in observed):
        raise BuildError(
            "production source freeze candidate is incomplete: "
            + ",".join(sorted(blockers))
        )
    rows = [
        {
            "path": row["path"], "role": row["role"],
            "sha256": row["sha256"], "size": row["size"],
        }
        for row in observed
    ]
    result = {
        "platform": "darwin-arm64",
        "roster_definition_sha256": _production_source_definition_sha256(),
        "schema": PRODUCTION_SOURCE_FREEZE_SCHEMA,
        "source_count": len(rows),
        "source_roster_sha256": _production_source_rows_sha256(rows),
        "sources": rows,
        "version": 2,
    }
    return _canonical_json_bytes(result)


def decode_production_source_freeze_manifest(raw: bytes) -> dict[str, Any]:
    """Strictly validate and canonically reproduce a source freeze manifest."""

    if not 1 <= len(raw) <= PRODUCTION_SOURCE_FREEZE_MAX_BYTES:
        raise BuildError("production source freeze manifest size is invalid")
    decoded = _strict_json_object(raw, "production source freeze manifest")
    if _canonical_json_bytes(decoded) != raw:
        raise BuildError("production source freeze manifest bytes are not canonical")
    if set(decoded) != {
        "platform", "roster_definition_sha256", "schema", "source_count",
        "source_roster_sha256", "sources", "version",
    }:
        raise BuildError("production source freeze manifest fields are not exact")
    if (
        decoded["schema"] != PRODUCTION_SOURCE_FREEZE_SCHEMA
        or decoded["version"] != 2
        or type(decoded["version"]) is not int
        or decoded["platform"] != "darwin-arm64"
        or decoded["roster_definition_sha256"]
        != _production_source_definition_sha256()
    ):
        raise BuildError("production source freeze manifest header differs")
    sources = decoded["sources"]
    if (
        type(sources) is not list
        or type(decoded["source_count"]) is not int
        or decoded["source_count"] != len(PRODUCTION_DARWIN_SOURCE_ROSTER)
        or len(sources) != decoded["source_count"]
    ):
        raise BuildError("production source freeze manifest count differs")
    for expected, row in zip(
        PRODUCTION_DARWIN_SOURCE_ROSTER, sources, strict=True
    ):
        role, relative = expected
        if type(row) is not dict or set(row) != {
            "path", "role", "sha256", "size",
        }:
            raise BuildError("production source freeze member fields are not exact")
        if (
            row["role"] != role or row["path"] != relative
            or type(row["sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
            or type(row["size"]) is not int
            or not 1 <= row["size"] <= PRODUCTION_SOURCE_MEMBER_MAX_BYTES
        ):
            raise BuildError("production source freeze member identity differs")
    if decoded["source_roster_sha256"] != _production_source_rows_sha256(sources):
        raise BuildError("production source freeze roster digest differs")
    return decoded


# These aliases emphasize that loaded Python can produce and decode review
# evidence only; neither function mints native build or installation authority.
TEST_ONLY_render_production_source_freeze_candidate = (
    render_production_source_freeze_candidate
)
TEST_ONLY_decode_production_source_freeze_manifest = (
    decode_production_source_freeze_manifest
)


def validate_native_supervisor_schema_v2(raw: bytes) -> dict[str, Any]:
    """Validate the packaged role-5 schema against the compiled ABI constants."""

    if not 1 <= len(raw) <= 1024 * 1024:
        raise BuildError("native supervisor schema size is invalid")
    document = _strict_json_object(raw, "native supervisor schema")
    if set(document) != {
        "authority_surface", "canonicalization", "frame_protocol", "limits",
        "projection", "schema", "service_bootstrap", "version_identifiers",
        "wire_primitives",
    } or document["schema"] != "plamen.native-supervisor.schema.v2":
        raise BuildError("native supervisor schema top-level contract differs")
    canonicalization = document.get("canonicalization")
    if type(canonicalization) is not dict or canonicalization.get(
        "duplicate_object_keys_allowed"
    ) is not False or canonicalization.get("floats_allowed") is not False:
        raise BuildError("native supervisor schema canonicalization differs")

    frame = document.get("frame_protocol")
    limits = document.get("limits")
    service = document.get("service_bootstrap")
    versions = document.get("version_identifiers")
    projection = document.get("projection")
    authorities = document.get("authority_surface")
    if not all(type(value) is dict for value in (
        frame, limits, service, versions, projection, authorities,
    )):
        raise BuildError("native supervisor schema sections are not objects")
    if (
        frame.get("magic_ascii") != "PLMBRK2"
        or frame.get("header_size") != 196
        or frame.get("network_byte_order") is not True
        or limits.get("frame_payload_bytes") != 2_097_152
        or limits.get("scm_rights_fds") != 16
        or limits.get("session_key_bytes") != 32
        or limits.get("session_id_bytes") != 32
        or limits.get("identifier_bytes") != 128
        or limits.get("text_bytes") != 4096
        or limits.get("projection_bytes") != 1_048_576
    ):
        raise BuildError("native supervisor schema frame ABI differs")
    envelope = service.get("service_envelope")
    if type(envelope) is not dict or envelope != {
        "header_size": 124,
        "maximum_fds": 15,
        "maximum_payload_bytes": 4096,
        "version": 2,
    }:
        raise BuildError("native supervisor schema service envelope ABI differs")
    if versions != {
        "backend_execution_abi_schema": (
            "plamen.posix_backend_execution.native.v2"
        ),
        "broker_abi_schema": "plamen.native-broker.v2",
        "broker_protocol_version": 2,
        "darwin_service_name": "com.plamen.audit.broker.v2",
        "linux_guest_socket": "/run/plamen/broker-v2.sock",
        "linux_service_name": "plamen-audit-broker-v2",
        "linux_user_socket_format": "/run/user/%llu/plamen/broker-v2.sock",
        "projection_schema": "plamen.native_audit_request_projection.v1",
        "supervisor_request_schema": "plamen.posix_audit_supervisor.v1",
    }:
        raise BuildError("native supervisor schema version identifiers differ")
    if (
        projection.get("projection_schema")
        != "plamen.native_audit_request_projection.v1"
        or projection.get("audit_request_schema")
        != "plamen.posix_audit_supervisor.v1"
        or projection.get("top_level_fields")
        != ["audit_request", "projection_schema"]
    ):
        raise BuildError("native supervisor schema projection ABI differs")
    outer = authorities.get("outer_supervisor")
    backend = authorities.get("backend_execution")
    if (
        type(outer) is not dict or outer.get("bundle_type")
        != "SupervisorAuthorities" or outer.get("initial_authority_role") != 1
        or outer.get("member_count") != 10
        or type(outer.get("members")) is not list
        or not all(type(row) is dict for row in outer.get("members", []))
        or [(row.get("ordinal"), row.get("name")) for row in outer["members"]]
        != [
            (1, "RuntimeImageAuthority"), (2, "WorkspaceAuthority"),
            (3, "BackendContextAuthority"), (4, "ProviderAuthority"),
            (5, "GuestAdmissionAuthority"), (6, "ExtinctionAuthority"),
            (7, "ArtifactAuthority"), (8, "ExportAuthority"),
            (9, "JournalAuthority"), (10, "RecoveryAuthority"),
        ]
        or type(backend) is not dict
        or backend.get("bundle_type") != "GuestDriverAuthorities"
        or backend.get("bundle_member_name") != "BackendExecutionAuthority"
        or backend.get("initial_authority_role") != 2
        or backend.get("member_count") != 1
        or backend.get("method_order") != [
            "prepare", "start_or_recover", "wait_or_recover",
            "read_output_or_recover", "extinguish_or_recover",
            "close_operation",
        ]
    ):
        raise BuildError("native supervisor schema authority ABI differs")
    return {
        "schema": document["schema"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "semantic_sha256": hashlib.sha256(
            _canonical_json_bytes(document)
        ).hexdigest(),
        "size": len(raw),
        "status": "EXACT_ABI_VALIDATED_DIAGNOSTIC_ONLY",
    }


TEST_ONLY_validate_native_supervisor_schema_v2 = (
    validate_native_supervisor_schema_v2
)


def _production_intrinsic_generation_material(
    artifact_roster: list[dict[str, Any]],
) -> tuple[bytes, bytes, bytes]:
    """Return generation ID, roster digest, and the exact ID preimage.

    The launchd plist and install receipt deliberately cannot enter this
    function: both contain deployment paths/vnodes that exist only after the
    intrinsic generation directory has its content address.
    """

    if type(artifact_roster) is not list or len(artifact_roster) != len(
        PRODUCTION_GENERATION_INTRINSIC_ROLES
    ):
        raise BuildError("intrinsic generation artifact roster is not exact")
    exact_keys = {"role", "relative_path", "sha256", "size", "mode"}
    rows = bytearray()
    for role_id, (expected_role, raw, receipt_member) in enumerate(zip(
        PRODUCTION_GENERATION_INTRINSIC_ROLES,
        artifact_roster,
        DARWIN_INSTALL_RECEIPT_V2_MEMBERS,
        strict=True,
    ), start=1):
        receipt_role, receipt_role_id, receipt_path, receipt_mode, _id, _signed = (
            receipt_member
        )
        if type(raw) is not dict or set(raw) != exact_keys:
            raise BuildError("intrinsic generation artifact fields are not exact")
        role = raw["role"]
        relative = raw["relative_path"]
        digest = raw["sha256"]
        size = raw["size"]
        mode = raw["mode"]
        if role != expected_role or role != receipt_role or role_id != receipt_role_id:
            raise BuildError("intrinsic generation artifact roles are not exact")
        if (
            type(relative) is not str
            or relative != receipt_path
            or relative != _safe_relative(relative)
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not any(bytes.fromhex(digest))
            or type(size) is not int
            or not 1 <= size < 1 << 64
            or type(mode) is not int
            or mode != receipt_mode
        ):
            raise BuildError("intrinsic generation artifact identity is invalid")
        path = relative.encode("ascii", "strict")
        rows.extend(struct.pack(">HHIQ", role_id, len(path), mode, size))
        rows.extend(bytes.fromhex(digest))
        rows.extend(path)
    preimage = bytearray(b"PLAMEN-INTRINSIC-GENERATION-V2\0")
    preimage.extend(struct.pack(">HHHH", 2, 1, 1, len(artifact_roster)))
    preimage.extend(rows)
    frozen = bytes(preimage)
    roster_digest = hashlib.sha256(
        b"PLAMEN-INTRINSIC-ROSTER-V2\0"
        + struct.pack(">H", len(artifact_roster)) + rows
    ).digest()
    return hashlib.sha256(frozen).digest(), roster_digest, frozen


def production_intrinsic_generation_id(
    artifact_roster: list[dict[str, Any]],
) -> tuple[str, bytes]:
    """Hash the acyclic, deployment-independent Darwin generation preimage."""

    generation, _roster, preimage = _production_intrinsic_generation_material(
        artifact_roster
    )
    return generation.hex(), preimage


def production_intrinsic_roster_sha256(
    artifact_roster: list[dict[str, Any]],
) -> str:
    """Derive receipt field 48 from the same exact nine member rows."""

    _generation, roster, _preimage = _production_intrinsic_generation_material(
        artifact_roster
    )
    return roster.hex()


def _receipt_v2_digest(value: Any, label: str) -> bytes:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise BuildError(f"{label} is not an exact SHA-256 digest")
    raw = bytes.fromhex(value)
    if not any(raw):
        raise BuildError(f"{label} cannot be the all-zero digest")
    return raw


def _receipt_v2_unsigned(value: Any, bits: int, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 1 << bits:
        raise BuildError(f"{label} is outside its unsigned integer bound")
    return value


def _receipt_v2_string(
    value: Any, maximum: int, label: str, *, absolute: bool,
) -> bytes:
    if type(value) is not str:
        raise BuildError(f"{label} is not an exact string")
    try:
        raw = value.encode("ascii", "strict")
    except UnicodeError as exc:
        raise BuildError(f"{label} is not canonical ASCII") from exc
    if (
        not raw or len(raw) > maximum
        or any(byte < 0x21 or byte > 0x7e for byte in raw)
    ):
        raise BuildError(f"{label} has invalid length or bytes")
    if b"\\" in raw or value.startswith("/") != absolute:
        raise BuildError(f"{label} has the wrong path kind")
    if (
        "//" in value or "/./" in value or "/../" in value
        or value.endswith("/.") or value.endswith("/..")
    ):
        raise BuildError(f"{label} is not a normalized path")
    return raw


def _receipt_v2_identity_string(
    value: Any, maximum: int, label: str, *, permit_empty: bool,
) -> bytes:
    if type(value) is not str:
        raise BuildError(f"{label} is not an exact string")
    try:
        raw = value.encode("ascii", "strict")
    except UnicodeError as exc:
        raise BuildError(f"{label} is not canonical ASCII") from exc
    if (
        (not permit_empty and not raw) or len(raw) > maximum
        or re.fullmatch(rb"[A-Za-z0-9.-]*", raw) is None
    ):
        raise BuildError(f"{label} is not a canonical signing identity")
    return raw


def TEST_ONLY_encode_darwin_install_receipt_v2(
    *,
    projection_schema_sha256: str,
    protocol_schema_sha256: str,
    python_micro: int,
    generation_path: str,
    broker_launchd_plist: dict[str, Any],
    custody_launchd_plist: dict[str, Any],
    members: list[dict[str, Any]],
) -> bytes:
    """Encode the frozen receipt ABI for parser interoperability tests only.

    Loaded Python has no production install authority; the native installer
    must independently serialize, retain, publish, and revalidate these facts.
    """

    plist_fields = {
        "path", "sha256", "size", "mode", "device", "inode", "uid", "gid",
    }
    if (
        type(broker_launchd_plist) is not dict
        or set(broker_launchd_plist) != plist_fields
        or type(custody_launchd_plist) is not dict
        or set(custody_launchd_plist) != plist_fields
    ):
        raise BuildError("launchd plist receipt fields are not exact")
    if type(members) is not list or len(members) != len(
        DARWIN_INSTALL_RECEIPT_V2_MEMBERS
    ):
        raise BuildError("receipt member roster is not exact")
    artifact_roster = [
        {
            "role": member.get("role"),
            "relative_path": member.get("relative_path"),
            "sha256": member.get("sha256"),
            "size": member.get("size"),
            "mode": member.get("mode"),
        }
        for member in members
        if type(member) is dict
    ]
    if len(artifact_roster) != len(members):
        raise BuildError("receipt member fields are not exact")
    generation_id_sha256, _preimage = production_intrinsic_generation_id(
        artifact_roster
    )
    intrinsic_roster_sha256 = production_intrinsic_roster_sha256(
        artifact_roster
    )
    record = bytearray(DARWIN_INSTALL_RECEIPT_V2_SIZE)
    record[0:8] = b"PLMINS2\0"
    struct.pack_into(">HHI", record, 8, 2, 256, DARWIN_INSTALL_RECEIPT_V2_SIZE)
    generation_digest = _receipt_v2_digest(generation_id_sha256, "generation id")
    record[16:48] = generation_digest
    record[48:80] = _receipt_v2_digest(
        intrinsic_roster_sha256, "intrinsic roster"
    )
    micro = _receipt_v2_unsigned(python_micro, 16, "Python micro version")
    if micro == 0:
        raise BuildError("Python micro version must be nonzero")
    abi = b"cpython-312-darwin"
    generation = _receipt_v2_string(
        generation_path, 1024, "generation path", absolute=True
    )
    broker_plist_path = _receipt_v2_string(
        broker_launchd_plist["path"], 1024,
        "broker launchd plist path", absolute=True
    )
    custody_plist_path = _receipt_v2_string(
        custody_launchd_plist["path"], 1024,
        "custody launchd plist path", absolute=True
    )
    if generation_path.rsplit("/", 1)[-1] != generation_id_sha256:
        raise BuildError("generation path basename is not the generation id")
    if broker_launchd_plist["path"] != (
        generation_path
        + "/Library/LaunchAgents/com.plamen.audit.broker.v2.plist"
    ):
        raise BuildError("broker launchd plist is not descriptor-ancestry bound")
    if custody_launchd_plist["path"] != (
        generation_path
        + "/Library/LaunchAgents/com.plamen.audit.process-custody.v2.plist"
    ):
        raise BuildError("custody launchd plist is not descriptor-ancestry bound")
    struct.pack_into(
        ">HHHHHHHH", record, 112,
        len(DARWIN_INSTALL_RECEIPT_V2_MEMBERS), 3, 12, micro,
        len(abi), len(generation), len(broker_plist_path),
        len(custody_plist_path),
    )
    record[128:160] = _receipt_v2_digest(
        projection_schema_sha256, "projection schema"
    )
    record[160:192] = _receipt_v2_digest(
        protocol_schema_sha256, "protocol schema"
    )
    record[256:256 + len(abi)] = abi
    record[320:320 + len(generation)] = generation
    record[1344:1344 + len(broker_plist_path)] = broker_plist_path
    record[11456:11456 + len(custody_plist_path)] = custody_plist_path
    record[2368:2400] = _receipt_v2_digest(
        broker_launchd_plist["sha256"], "broker launchd plist"
    )
    plist_values = (
        _receipt_v2_unsigned(broker_launchd_plist["size"], 64, "broker launchd plist size"),
        _receipt_v2_unsigned(broker_launchd_plist["device"], 64, "broker launchd plist device"),
        _receipt_v2_unsigned(broker_launchd_plist["inode"], 64, "broker launchd plist inode"),
    )
    if 0 in plist_values:
        raise BuildError("launchd plist retained identity cannot contain zero")
    if broker_launchd_plist["mode"] != 0o400:
        raise BuildError("broker launchd plist mode is not exact")
    struct.pack_into(
        ">QQQIII", record, 2400, *plist_values, 0o400,
        _receipt_v2_unsigned(broker_launchd_plist["uid"], 32, "broker launchd plist uid"),
        _receipt_v2_unsigned(broker_launchd_plist["gid"], 32, "broker launchd plist gid"),
    )
    record[12480:12512] = _receipt_v2_digest(
        custody_launchd_plist["sha256"], "custody launchd plist"
    )
    custody_values = (
        _receipt_v2_unsigned(custody_launchd_plist["size"], 64, "custody launchd plist size"),
        _receipt_v2_unsigned(custody_launchd_plist["device"], 64, "custody launchd plist device"),
        _receipt_v2_unsigned(custody_launchd_plist["inode"], 64, "custody launchd plist inode"),
    )
    if 0 in custody_values:
        raise BuildError("custody launchd plist retained identity cannot contain zero")
    if custody_launchd_plist["mode"] != 0o400:
        raise BuildError("custody launchd plist mode is not exact")
    struct.pack_into(
        ">QQQIII", record, 12512, *custody_values, 0o400,
        _receipt_v2_unsigned(custody_launchd_plist["uid"], 32, "custody launchd plist uid"),
        _receipt_v2_unsigned(custody_launchd_plist["gid"], 32, "custody launchd plist gid"),
    )

    member_fields = {
        "role", "relative_path", "sha256", "size", "mode", "device",
        "inode", "uid", "gid", "signing_identifier", "team_identifier",
        "cdhash",
    }
    for index, (expected, member) in enumerate(
        zip(DARWIN_INSTALL_RECEIPT_V2_MEMBERS, members, strict=True)
    ):
        role, role_id, path, mode, required_identifier, signed = expected
        if type(member) is not dict or set(member) != member_fields:
            raise BuildError("receipt member fields are not exact")
        if (
            member["role"] != role or member["relative_path"] != path
            or member["mode"] != mode
        ):
            raise BuildError("receipt member roster/order is not exact")
        relative = _receipt_v2_string(
            member["relative_path"], 256, "member relative path", absolute=False
        )
        identifier = _receipt_v2_identity_string(
            member["signing_identifier"], 128, "member signing identifier",
            permit_empty=not signed,
        )
        team = _receipt_v2_identity_string(
            member["team_identifier"], 128, "member team identifier",
            permit_empty=True,
        )
        cdhash_text = member["cdhash"]
        pattern = r"(?:[0-9a-f]{40}|[0-9a-f]{64})" if signed else r""
        if type(cdhash_text) is not str or re.fullmatch(pattern, cdhash_text) is None:
            raise BuildError("receipt member CDHash is not exact")
        cdhash = bytes.fromhex(cdhash_text)
        if not signed and (identifier or team):
            raise BuildError("unsigned receipt member has signing identity")
        if required_identifier is not None and identifier.decode() != required_identifier:
            raise BuildError("receipt member signing identifier is not exact")
        if (
            role_id <= 3
            or role in {"install_coordinator", "source_bootstrap_coordinator"}
        ) and team:
            raise BuildError("ad-hoc production member team must be empty")
        values = (
            _receipt_v2_unsigned(member["size"], 64, "member size"),
            _receipt_v2_unsigned(member["device"], 64, "member device"),
            _receipt_v2_unsigned(member["inode"], 64, "member inode"),
        )
        if 0 in values:
            raise BuildError("receipt member retained identity cannot contain zero")
        offset = 2496 + index * 896
        struct.pack_into(
            ">HHHHHHIQQQII", record, offset,
            role_id, len(relative), len(identifier), len(team), len(cdhash), 0,
            mode, *values,
            _receipt_v2_unsigned(member["uid"], 32, "member uid"),
            _receipt_v2_unsigned(member["gid"], 32, "member gid"),
        )
        record[offset + 48:offset + 80] = _receipt_v2_digest(
            member["sha256"], "member"
        )
        record[offset + 80:offset + 80 + len(cdhash)] = cdhash
        record[offset + 112:offset + 112 + len(relative)] = relative
        record[offset + 368:offset + 368 + len(identifier)] = identifier
        record[offset + 496:offset + 496 + len(team)] = team
    checkpoint_view = bytes(record[:DARWIN_INSTALL_RECEIPT_V2_HASHED_SIZE])
    record[80:112] = hashlib.sha256(
        b"PLAMEN-INSTALL-PRECOMMIT-V2\0" + checkpoint_view
    ).digest()
    record[DARWIN_INSTALL_RECEIPT_V2_HASHED_SIZE:] = hashlib.sha256(
        record[:DARWIN_INSTALL_RECEIPT_V2_HASHED_SIZE]
    ).digest()
    return bytes(record)


def _darwin_profile_text(
    value: Any, maximum: int, label: str, *, component: bool,
) -> bytes:
    if type(value) is not str:
        raise BuildError(f"{label} is not an exact string")
    try:
        raw = value.encode("ascii", "strict")
    except UnicodeError as exc:
        raise BuildError(f"{label} is not canonical ASCII") from exc
    if (
        not raw or len(raw) > maximum
        or any(byte < 0x20 or byte > 0x7e for byte in raw)
        or b"\\" in raw or b"\n" in raw or b"\r" in raw or b"\t" in raw
        or component and b"/" in raw
    ):
        raise BuildError(f"{label} has invalid bytes or length")
    return raw


def encode_darwin_backend_profile_v2(
    *,
    provider_sha256: str,
    backend_sha256: str,
    provider_cdhash: str,
    backend_cdhash: str,
    provider_identifier: str,
    provider_team: str,
    provider_version: str,
    backend_identifier: str,
    backend_team: str,
    backend_version: str,
    backend_release: str,
    backend_selector: str,
    provider_selector: str,
    acquisition_policy_sha256: str,
) -> bytes:
    """Encode one exact launcher-consumed Darwin backend profile.

    Observation of the two executable descriptors/signatures/versions is a
    separate production-authority step.  This function accepts no paths and
    cannot weaken that admission boundary.
    """

    backend_identity = DARWIN_BACKEND_PROFILE_V2_IDENTITIES.get(
        backend_selector
    )
    if backend_identity is None:
        raise BuildError("Darwin backend profile selector is unsupported")
    fixed = {
        "provider_identifier": DARWIN_CODEX_PROFILE_V2_PROVIDER_IDENTIFIER,
        "provider_team": DARWIN_CODEX_PROFILE_V2_PROVIDER_TEAM,
        "backend_identifier": backend_identity["backend_identifier"],
        "backend_team": backend_identity["backend_team"],
        "backend_selector": backend_selector,
        "provider_selector": DARWIN_CODEX_PROFILE_V2_PROVIDER_SELECTOR,
    }
    observed = {
        "provider_identifier": provider_identifier,
        "provider_team": provider_team,
        "backend_identifier": backend_identifier,
        "backend_team": backend_team,
        "backend_selector": backend_selector,
        "provider_selector": provider_selector,
    }
    if observed != fixed:
        raise BuildError("Darwin backend profile fixed identity differs")
    provider_digest = _receipt_v2_digest(
        provider_sha256, "Darwin provider executable"
    )
    backend_digest = _receipt_v2_digest(
        backend_sha256, f"Darwin {backend_selector} executable"
    )
    cdhashes: list[bytes] = []
    for value, label in (
        (provider_cdhash, "Darwin provider CDHash"),
        (backend_cdhash, f"Darwin {backend_selector} CDHash"),
    ):
        if (
            type(value) is not str
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None
        ):
            raise BuildError(f"{label} is not exact")
        decoded = bytes.fromhex(value)
        if not any(decoded):
            raise BuildError(f"{label} cannot be all-zero")
        cdhashes.append(decoded)
    text_values = (
        (provider_identifier, 128, "provider identifier", False),
        (provider_team, 128, "provider team", False),
        (provider_version, 128, "provider version", False),
        (backend_identifier, 128, "backend identifier", False),
        (backend_team, 128, "backend team", False),
        (backend_version, 128, "backend version", False),
        (backend_release, 256, "backend release", True),
        (backend_selector, 32, "backend selector", True),
        (provider_selector, 32, "provider selector", True),
    )
    texts = [
        _darwin_profile_text(value, maximum, label, component=component)
        for value, maximum, label, component in text_values
    ]
    if not provider_version.startswith("container CLI version "):
        raise BuildError("Darwin provider version is not exact")
    if re.fullmatch(r"[0-9a-f]{64}", acquisition_policy_sha256) is None:
        raise BuildError("Darwin backend acquisition policy digest differs")
    if backend_selector == "codex":
        match = re.fullmatch(
            r"([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)-"
            r"aarch64-apple-darwin", backend_release,
        )
        if match is None or backend_version != f"codex-cli {match.group(1)}":
            raise BuildError("Darwin Codex resolved release differs")
    elif (
        re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?",
            backend_release,
        ) is None
        or backend_version != f"{backend_release} (Claude Code)"
    ):
        raise BuildError("Darwin Claude resolved release differs")

    record = bytearray(DARWIN_CODEX_PROFILE_V2_SIZE)
    record[:8] = DARWIN_CODEX_PROFILE_V2_MAGIC
    struct.pack_into(
        ">HHII", record, 8, DARWIN_CODEX_PROFILE_V2_VERSION,
        DARWIN_CODEX_PROFILE_V2_HEADER_SIZE, DARWIN_CODEX_PROFILE_V2_SIZE, 1,
    )
    record[32:64] = provider_digest
    record[64:96] = backend_digest
    record[96:96 + len(cdhashes[0])] = cdhashes[0]
    record[128:128 + len(cdhashes[1])] = cdhashes[1]
    record[182:214] = bytes.fromhex(acquisition_policy_sha256)
    struct.pack_into(
        ">" + "H" * 11, record, 160,
        len(cdhashes[0]), len(cdhashes[1]), *(len(value) for value in texts),
    )
    slots = (
        (256, 128), (384, 128), (512, 128), (640, 128), (768, 128),
        (896, 128), (1024, 256), (1280, 32), (1312, 32),
    )
    for value, (offset, _size) in zip(texts, slots, strict=True):
        record[offset:offset + len(value)] = value
    record[DARWIN_CODEX_PROFILE_V2_HASHED_SIZE:] = hashlib.sha256(
        record[:DARWIN_CODEX_PROFILE_V2_HASHED_SIZE]
    ).digest()
    return bytes(record)


def encode_darwin_codex_profile_v2(**values: Any) -> bytes:
    """Compatibility wrapper for the exact Codex member of the roster."""

    if values.get("backend_selector") != DARWIN_CODEX_PROFILE_V2_BACKEND_SELECTOR:
        raise BuildError("Darwin Codex profile selector differs")
    return encode_darwin_backend_profile_v2(**values)


def encode_darwin_claude_profile_v2(**values: Any) -> bytes:
    """Encode the exact Claude member of the Darwin backend roster."""

    if values.get("backend_selector") != DARWIN_CLAUDE_PROFILE_V2_BACKEND_SELECTOR:
        raise BuildError("Darwin Claude profile selector differs")
    return encode_darwin_backend_profile_v2(**values)


def decode_darwin_backend_profile_v2(raw: bytes) -> dict[str, str]:
    """Strictly decode and canonically reproduce one backend profile."""

    if type(raw) is not bytes or len(raw) != DARWIN_CODEX_PROFILE_V2_SIZE:
        raise BuildError("Darwin backend profile size differs")
    if raw[:8] != DARWIN_CODEX_PROFILE_V2_MAGIC:
        raise BuildError("Darwin backend profile magic differs")
    if struct.unpack_from(">HHII", raw, 8) != (
        DARWIN_CODEX_PROFILE_V2_VERSION,
        DARWIN_CODEX_PROFILE_V2_HEADER_SIZE,
        DARWIN_CODEX_PROFILE_V2_SIZE,
        1,
    ):
        raise BuildError("Darwin backend profile header differs")
    if (
        any(raw[20:32])
        or not any(raw[182:214])
        or any(raw[214:256])
        or any(
        raw[1344:DARWIN_CODEX_PROFILE_V2_HASHED_SIZE]
        )
    ):
        raise BuildError("Darwin backend profile reserved bytes differ")
    if not secrets.compare_digest(
        raw[DARWIN_CODEX_PROFILE_V2_HASHED_SIZE:],
        hashlib.sha256(raw[:DARWIN_CODEX_PROFILE_V2_HASHED_SIZE]).digest(),
    ):
        raise BuildError("Darwin backend profile trailer digest differs")
    lengths = struct.unpack_from(">" + "H" * 11, raw, 160)
    cdhash_lengths = lengths[:2]
    if any(size not in (20, 32) for size in cdhash_lengths):
        raise BuildError("Darwin backend profile CDHash size differs")
    for offset, size in zip((96, 128), cdhash_lengths, strict=True):
        if not any(raw[offset:offset + size]) or any(raw[offset + size:offset + 32]):
            raise BuildError("Darwin backend profile CDHash padding differs")
    slots = (
        (256, 128), (384, 128), (512, 128), (640, 128), (768, 128),
        (896, 128), (1024, 256), (1280, 32), (1312, 32),
    )
    labels = (
        "provider_identifier", "provider_team", "provider_version",
        "backend_identifier", "backend_team", "backend_version",
        "backend_release", "backend_selector", "provider_selector",
    )
    values: dict[str, str] = {}
    for label, size, (offset, slot_size) in zip(
        labels, lengths[2:], slots, strict=True
    ):
        if size == 0 or size > slot_size or any(raw[offset + size:offset + slot_size]):
            raise BuildError("Darwin backend profile text padding differs")
        try:
            values[label] = raw[offset:offset + size].decode("ascii", "strict")
        except UnicodeError as exc:
            raise BuildError("Darwin backend profile text is not ASCII") from exc
    result = {
        "provider_sha256": raw[32:64].hex(),
        "backend_sha256": raw[64:96].hex(),
        "provider_cdhash": raw[96:96 + cdhash_lengths[0]].hex(),
        "backend_cdhash": raw[128:128 + cdhash_lengths[1]].hex(),
        "acquisition_policy_sha256": raw[182:214].hex(),
        **values,
    }
    if encode_darwin_backend_profile_v2(**result) != raw:
        raise BuildError("Darwin backend profile is not canonical")
    return result


def decode_darwin_codex_profile_v2(raw: bytes) -> dict[str, str]:
    result = decode_darwin_backend_profile_v2(raw)
    if result["backend_selector"] != DARWIN_CODEX_PROFILE_V2_BACKEND_SELECTOR:
        raise BuildError("Darwin Codex profile selector differs")
    return result


def decode_darwin_claude_profile_v2(raw: bytes) -> dict[str, str]:
    result = decode_darwin_backend_profile_v2(raw)
    if result["backend_selector"] != DARWIN_CLAUDE_PROFILE_V2_BACKEND_SELECTOR:
        raise BuildError("Darwin Claude profile selector differs")
    return result


def _run_profile_observation(
    argv: list[str], *, label: str, maximum: int = 64 * 1024,
) -> bytes:
    try:
        completed = subprocess.run(
            argv, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=_CLOSED_ENV, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError(f"{label} observation failed") from exc
    combined = completed.stdout + completed.stderr
    if completed.returncode != 0 or not combined or len(combined) > maximum:
        raise BuildError(f"{label} observation failed")
    return combined


def _darwin_codesign_identity(path: Path, label: str) -> dict[str, str]:
    _run_profile_observation(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", str(path)],
        label=f"{label} strict code signature",
    )
    output = _run_profile_observation(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
        label=f"{label} code identity",
    ).decode("utf-8", "strict")
    fields: dict[str, str] = {}
    for line in output.splitlines():
        for key in ("Identifier", "TeamIdentifier", "CDHash"):
            prefix = key + "="
            if line.startswith(prefix):
                if key in fields:
                    raise BuildError(f"{label} code identity is ambiguous")
                fields[key] = line[len(prefix):]
    if set(fields) != {"Identifier", "TeamIdentifier", "CDHash"}:
        raise BuildError(f"{label} code identity is incomplete")
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", fields["CDHash"]) is None:
        raise BuildError(f"{label} CDHash is malformed")
    return {
        "identifier": fields["Identifier"],
        "team": fields["TeamIdentifier"],
        "cdhash": fields["CDHash"],
    }


def _darwin_codesign_full_sha256(path: Path, label: str) -> str:
    output = _run_profile_observation(
        ["/usr/bin/codesign", "-d", "--verbose=5", str(path)],
        label=f"{label} full code identity",
    ).decode("utf-8", "strict")
    values = [
        line.removeprefix("CandidateCDHashFull sha256=")
        for line in output.splitlines()
        if line.startswith("CandidateCDHashFull sha256=")
    ]
    if len(values) != 1 or re.fullmatch(r"[0-9a-f]{64}", values[0]) is None:
        raise BuildError(f"{label} full code-directory digest differs")
    return values[0]


def _darwin_codesign_requirement(
    path: Path, label: str, requirement: str,
) -> None:
    if (
        type(requirement) is not str or not requirement
        or "\x00" in requirement or "\n" in requirement or "\r" in requirement
    ):
        raise BuildError(f"{label} requirement is malformed")
    try:
        completed = subprocess.run(
            [
                "/usr/bin/codesign", "--verify", "--strict",
                "-R=" + requirement, str(path),
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=_CLOSED_ENV, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError(f"{label} requirement validation failed") from exc
    if (
        completed.returncode != 0 or completed.stdout
        or len(completed.stderr) > MAX_COMPILER_OUTPUT_BYTES
    ):
        raise BuildError(f"{label} requirement validation failed")


def _darwin_profile_version(path: Path, label: str) -> str:
    output = _run_profile_observation(
        [str(path), "--version"], label=f"{label} version"
    )
    try:
        value = output.decode("ascii", "strict")
    except UnicodeError as exc:
        raise BuildError(f"{label} version is not ASCII") from exc
    if not value.endswith("\n") or "\n" in value[:-1] or "\r" in value:
        raise BuildError(f"{label} version output is not one exact line")
    return _darwin_profile_text(
        value[:-1], 128, f"{label} version", component=False
    ).decode("ascii")


def _open_owned_managed_directory_tree(
    home: Path, relative_parent: PurePosixPath,
) -> int:
    """Open/create a private user-owned directory chain without following links."""

    if not relative_parent.parts or relative_parent.is_absolute():
        raise BuildError("managed backend parent is not relative")
    descriptor = _open_directory_nofollow(home)
    try:
        for component in relative_parent.parts:
            if (
                _SAFE_COMPONENT.fullmatch(component) is None
                and component != ".local"
            ):
                raise BuildError("managed backend directory component differs")
            try:
                os.mkdir(component, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
            except FileExistsError:
                pass
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            info = os.fstat(child)
            named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISDIR(info.st_mode) or not _same_stat(info, named)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                os.close(child)
                raise BuildError("managed backend directory authority differs")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def stage_darwin_backend_profiles_v2(
    runtime_root: Path, codex_profile: bytes, claude_profile: bytes,
) -> dict[str, Any]:
    """Write both exact profiles into one empty private runtime projection.

    The runtime manifest subsequently censuses these bytes and the native
    generation stager revalidates that entire manifest before copying it.
    Profile bytes therefore reach the install receipt only through its exact
    role-8 runtime-manifest member, never through an ambient launcher path.
    """

    decoded = {
        "codex": decode_darwin_codex_profile_v2(codex_profile),
        "claude": decode_darwin_claude_profile_v2(claude_profile),
    }
    if (
        decoded["codex"]["acquisition_policy_sha256"]
        != decoded["claude"]["acquisition_policy_sha256"]
    ):
        raise BuildError("Darwin backend profile policy generations differ")
    root_fd = profiles_fd = codex_fd = claude_fd = -1
    try:
        root_fd = _open_directory_nofollow(
            _canonical_absolute_path(runtime_root, "private runtime root")
        )
        root_info = os.fstat(root_fd)
        if (
            root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise BuildError("private runtime root authority differs")
        profiles_fd = _mkdir_new(root_fd, "profiles")
        codex_fd, codex_identity = _write_new_retained(
            profiles_fd, "codex-v2.bin", codex_profile, 0o400,
        )
        claude_fd, claude_identity = _write_new_retained(
            profiles_fd, "claude-v2.bin", claude_profile, 0o400,
        )
        os.fchmod(profiles_fd, 0o500)
        os.fsync(profiles_fd); os.fsync(root_fd)
        for descriptor, identity, raw, selector in (
            (codex_fd, codex_identity, codex_profile, "codex"),
            (claude_fd, claude_identity, claude_profile, "claude"),
        ):
            current = os.fstat(descriptor)
            if (
                stat.S_IMODE(current.st_mode) != 0o400
                or current.st_uid != os.geteuid() or current.st_nlink != 1
                or current.st_size != len(raw)
                or _sha256_fd(descriptor, current.st_size)
                != identity["sha256"]
            ):
                raise BuildError(f"staged {selector} profile drifted")
        return {
            "schema": "plamen.darwin-backend-profile-stage.v2",
            "acquisition_policy_sha256": decoded["codex"][
                "acquisition_policy_sha256"
            ],
            "profiles": {
                selector: {
                    "relative_path": DARWIN_BACKEND_PROFILE_V2_IDENTITIES[selector][
                        "runtime_path"
                    ],
                    "sha256": (
                        codex_identity if selector == "codex" else claude_identity
                    )["sha256"],
                    "size": DARWIN_CODEX_PROFILE_V2_SIZE,
                    "backend_sha256": decoded[selector]["backend_sha256"],
                }
                for selector in ("codex", "claude")
            },
        }
    finally:
        for descriptor in (claude_fd, codex_fd, profiles_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)


def _runtime_manifest_path(raw: bytes) -> str:
    if not raw or len(raw) > RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES:
        raise BuildError("runtime manifest path length is outside its bound")
    try:
        path = raw.decode("ascii", "strict")
    except UnicodeError as exc:
        raise BuildError("runtime manifest path is not canonical ASCII") from exc
    if path != _safe_relative(path) or len(PurePosixPath(path).parts) > (
        RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH
    ):
        raise BuildError("runtime manifest path is not canonical")
    return path


def _runtime_manifest_scan(runtime_root: Path) -> list[dict[str, Any]]:
    """Census a retained runtime tree without following a directory entry.

    This is source material for TEST_ONLY manifest generation.  Production
    installation must perform the equivalent walk in its native retained-FD
    transaction; loaded Python cannot confer publication authority.
    """

    path = Path(os.path.abspath(os.fspath(runtime_root)))
    flags = (
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        named_root = os.stat(path, follow_symlinks=False)
        root_fd = os.open(path, flags)
    except OSError as exc:
        raise BuildError("runtime package root cannot be retained exactly") from exc
    try:
        opened_root = os.fstat(root_fd)
        if not _same_stat(named_root, opened_root):
            raise BuildError("runtime package root changed during admission")
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or stat.S_IMODE(opened_root.st_mode) != 0o500
        ):
            raise BuildError("runtime package root mode is not exact")

        rows: list[dict[str, Any]] = []
        folded: set[str] = set()
        total_file_bytes = 0

        def visit(directory_fd: int, prefix: str, depth: int) -> None:
            nonlocal total_file_bytes
            try:
                names_before = os.listdir(directory_fd)
            except OSError as exc:
                raise BuildError("runtime directory census failed") from exc
            if len(names_before) > RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES:
                raise BuildError("runtime directory census exceeds its bound")
            encoded_names: list[tuple[bytes, str]] = []
            for name in names_before:
                if type(name) is not str or _SAFE_COMPONENT.fullmatch(name) is None:
                    raise BuildError("runtime package contains a non-canonical name")
                try:
                    encoded = name.encode("ascii", "strict")
                except UnicodeError as exc:
                    raise BuildError(
                        "runtime package name is not canonical ASCII"
                    ) from exc
                encoded_names.append((encoded, name))
            encoded_names.sort(key=lambda item: item[0])
            if len({item[0] for item in encoded_names}) != len(encoded_names):
                raise BuildError("runtime directory census contains duplicates")

            for _encoded, name in encoded_names:
                relative = f"{prefix}/{name}" if prefix else name
                path_bytes = relative.encode("ascii", "strict")
                relative = _runtime_manifest_path(path_bytes)
                current_depth = len(PurePosixPath(relative).parts)
                if current_depth != depth + 1:
                    raise BuildError("runtime package depth accounting failed")
                folded_path = relative.casefold()
                if folded_path in folded:
                    raise BuildError("runtime package contains case-colliding paths")
                folded.add(folded_path)
                try:
                    named_before = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                except OSError as exc:
                    raise BuildError("runtime package entry cannot be inspected") from exc

                common_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                if stat.S_ISDIR(named_before.st_mode):
                    try:
                        child_fd = os.open(
                            name,
                            common_flags | os.O_DIRECTORY
                            | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=directory_fd,
                        )
                    except OSError as exc:
                        raise BuildError(
                            "runtime directory cannot be retained without a link"
                        ) from exc
                    try:
                        opened = os.fstat(child_fd)
                        if not _same_stat(named_before, opened):
                            raise BuildError(
                                "runtime directory changed during admission"
                            )
                        if stat.S_IMODE(opened.st_mode) != 0o500:
                            raise BuildError("runtime directory mode is not exact")
                        rows.append({
                            "kind": RUNTIME_PACKAGE_MANIFEST_V2_DIRECTORY,
                            "path": relative,
                            "mode": 0o500,
                            "size": 0,
                            "link_count": 0,
                            "depth": current_depth,
                            "sha256": bytes(32),
                        })
                        if len(rows) > RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES:
                            raise BuildError(
                                "runtime package entry census exceeds its bound"
                            )
                        visit(child_fd, relative, current_depth)
                        opened_after = os.fstat(child_fd)
                        try:
                            named_after = os.stat(
                                name, dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                        except OSError as exc:
                            raise BuildError(
                                "runtime directory disappeared during admission"
                            ) from exc
                        if (
                            not _same_stat(opened, opened_after)
                            or not _same_stat(opened_after, named_after)
                        ):
                            raise BuildError(
                                "runtime directory changed during admission"
                            )
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(named_before.st_mode):
                    try:
                        file_fd = os.open(
                            name,
                            common_flags | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=directory_fd,
                        )
                    except OSError as exc:
                        raise BuildError(
                            "runtime file cannot be retained without a link"
                        ) from exc
                    try:
                        opened = os.fstat(file_fd)
                        if not _same_stat(named_before, opened):
                            raise BuildError("runtime file changed during admission")
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or stat.S_IMODE(opened.st_mode) != 0o400
                        ):
                            raise BuildError("runtime file mode is not exact")
                        if opened.st_nlink != 1:
                            raise BuildError("runtime file link count is not exact")
                        if not 0 <= opened.st_size <= (
                            RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES
                        ):
                            raise BuildError("runtime file size exceeds its bound")
                        total_file_bytes += opened.st_size
                        if total_file_bytes > (
                            RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES
                        ):
                            raise BuildError(
                                "runtime package byte census exceeds its bound"
                            )
                        digest = bytes.fromhex(_sha256_fd(file_fd, opened.st_size))
                        opened_after = os.fstat(file_fd)
                        try:
                            named_after = os.stat(
                                name, dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                        except OSError as exc:
                            raise BuildError(
                                "runtime file disappeared during admission"
                            ) from exc
                        if (
                            not _same_stat(opened, opened_after)
                            or not _same_stat(opened_after, named_after)
                        ):
                            raise BuildError("runtime file changed during admission")
                        rows.append({
                            "kind": RUNTIME_PACKAGE_MANIFEST_V2_FILE,
                            "path": relative,
                            "mode": 0o400,
                            "size": int(opened.st_size),
                            "link_count": 1,
                            "depth": current_depth,
                            "sha256": digest,
                        })
                        if len(rows) > RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES:
                            raise BuildError(
                                "runtime package entry census exceeds its bound"
                            )
                    finally:
                        os.close(file_fd)
                else:
                    raise BuildError(
                        "runtime package contains a symlink or special file"
                    )

            try:
                names_after = os.listdir(directory_fd)
            except OSError as exc:
                raise BuildError("runtime directory revalidation failed") from exc
            if sorted(names_before) != sorted(names_after):
                raise BuildError("runtime directory census changed during admission")

        visit(root_fd, "", 0)
        root_after = os.fstat(root_fd)
        try:
            named_root_after = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise BuildError("runtime package root disappeared during admission") from exc
        if (
            not _same_stat(opened_root, root_after)
            or not _same_stat(root_after, named_root_after)
        ):
            raise BuildError("runtime package root changed during admission")
    finally:
        os.close(root_fd)

    rows.sort(key=lambda row: row["path"].encode("ascii", "strict"))
    paths = {row["path"] for row in rows if row["kind"] == (
        RUNTIME_PACKAGE_MANIFEST_V2_FILE
    )}
    missing = set(RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES) - paths
    if missing:
        raise BuildError("runtime package required entrypoints are absent")
    return rows


def _runtime_manifest_reference(value: Any, label: str) -> bytes:
    if type(value) is not str or value != value.strip():
        raise BuildError(f"runtime binding {label} is not canonical")
    try:
        # OCI references and the frozen init path use the printable-ASCII
        # canonical subset of UTF-8.  Keeping the wire subset exact avoids
        # platform-dependent Unicode normalization in the native validator.
        raw = value.encode("ascii", "strict")
    except UnicodeError as exc:
        raise BuildError(
            f"runtime binding {label} is not canonical UTF-8/ASCII"
        ) from exc
    if (
        not raw or len(raw) > 511 or b"\0" in raw
        or any(byte < 0x21 or byte > 0x7e for byte in raw)
    ):
        raise BuildError(f"runtime binding {label} is outside its byte policy")
    return raw


def _runtime_manifest_binding(bindings: dict[str, Any]) -> bytes:
    exact_fields = {
        "target_arch",
        *RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_FIELDS,
        *RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS,
    }
    if type(bindings) is not dict or set(bindings) != exact_fields:
        raise BuildError("runtime external binding fields are not exact")
    target_arch = bindings["target_arch"]
    if type(target_arch) is not str or target_arch not in (
        RUNTIME_PACKAGE_MANIFEST_V2_TARGET_ARCHES
    ):
        raise BuildError("runtime target architecture is not exact")
    image_reference = _runtime_manifest_reference(
        bindings["oci_image_reference"], "OCI image reference"
    )
    init_reference = _runtime_manifest_reference(
        bindings["oci_init_reference"], "OCI init reference"
    )
    if init_reference.decode("utf-8") != RUNTIME_PACKAGE_MANIFEST_V2_INIT_REFERENCE:
        raise BuildError("runtime OCI init reference is not the frozen bootstrap path")

    digests: list[bytes] = []
    for field in RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS:
        value = bindings[field]
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise BuildError(f"runtime binding {field} is not an exact raw32 digest")
        digest = bytes.fromhex(value)
        if not any(digest):
            raise BuildError(f"runtime binding {field} is the zero digest")
        digests.append(digest)
    index_digest = bindings["oci_index_digest"]
    image_text = image_reference.decode("utf-8")
    if image_text != f"sha256:{index_digest}" and not image_text.endswith(
        f"@sha256:{index_digest}"
    ):
        raise BuildError("runtime OCI image reference is not index-digest-selected")

    encoded = bytearray(RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE)
    encoded[0:8] = RUNTIME_PACKAGE_MANIFEST_V2_BINDING_MAGIC
    struct.pack_into(
        ">HHHHHHHH", encoded, 8,
        RUNTIME_PACKAGE_MANIFEST_V2_VERSION,
        RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE,
        RUNTIME_PACKAGE_MANIFEST_V2_TARGET_ARCHES[target_arch],
        len(RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_FIELDS),
        len(image_reference), len(init_reference),
        len(RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS),
        RUNTIME_PACKAGE_MANIFEST_V2_BINDING_FLAGS,
    )
    encoded[32:64] = RUNTIME_PACKAGE_MANIFEST_V2_FIELD_ORDER_KAT
    for index, digest in enumerate(digests):
        offset = 64 + index * 32
        encoded[offset:offset + 32] = digest
    encoded[512:512 + len(image_reference)] = image_reference
    encoded[1024:1024 + len(init_reference)] = init_reference
    return bytes(encoded)


def _runtime_manifest_decode_binding(raw: bytes) -> dict[str, Any]:
    if len(raw) != RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE:
        raise BuildError("runtime external binding size is not exact")
    if raw[:8] != RUNTIME_PACKAGE_MANIFEST_V2_BINDING_MAGIC:
        raise BuildError("runtime external binding magic is invalid")
    (
        version, section_size, arch_id, reference_count, image_length,
        init_length, digest_count, flags,
    ) = struct.unpack_from(">HHHHHHHH", raw, 8)
    reverse_arches = {
        value: key for key, value in RUNTIME_PACKAGE_MANIFEST_V2_TARGET_ARCHES.items()
    }
    if (
        version != RUNTIME_PACKAGE_MANIFEST_V2_VERSION
        or section_size != RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
        or arch_id not in reverse_arches
        or reference_count != len(RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_FIELDS)
        or not 1 <= image_length <= 511
        or not 1 <= init_length <= 511
        or digest_count != len(RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS)
        or flags != RUNTIME_PACKAGE_MANIFEST_V2_BINDING_FLAGS
        or any(raw[24:32])
        or not secrets.compare_digest(
            raw[32:64], RUNTIME_PACKAGE_MANIFEST_V2_FIELD_ORDER_KAT
        )
    ):
        raise BuildError("runtime external binding header is not exact")
    digest_end = 64 + 32 * digest_count
    if digest_end != 512 or any(raw[1536:]):
        raise BuildError("runtime external binding reserved bytes are nonzero")
    digests: dict[str, str] = {}
    for index, field in enumerate(RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS):
        digest = raw[64 + index * 32:96 + index * 32]
        if not any(digest):
            raise BuildError(f"runtime binding {field} is the zero digest")
        digests[field] = digest.hex()
    image_slot = raw[512:1024]
    init_slot = raw[1024:1536]
    if any(image_slot[image_length:]) or any(init_slot[init_length:]):
        raise BuildError("runtime external binding reference padding is nonzero")
    try:
        image = image_slot[:image_length].decode("ascii", "strict")
        init = init_slot[:init_length].decode("ascii", "strict")
    except UnicodeError as exc:
        raise BuildError("runtime external binding reference is not UTF-8") from exc
    decoded = {
        "target_arch": reverse_arches[arch_id],
        "oci_image_reference": image,
        "oci_init_reference": init,
        **digests,
    }
    # Re-encoding proves normalization, reference/digest correspondence and
    # all currently reserved bytes in one exact comparison.
    if not secrets.compare_digest(_runtime_manifest_binding(decoded), raw):
        raise BuildError("runtime external binding is not canonical")
    return decoded


def _runtime_manifest_encode(
    rows: list[dict[str, Any]], bindings: dict[str, Any],
) -> bytes:
    if not 1 <= len(rows) <= RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES:
        raise BuildError("runtime package entry census is outside its bound")
    row_region = bytearray(len(rows) * RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE)
    directories = 0
    files = 0
    total_file_bytes = 0
    previous: bytes | None = None
    folded: set[str] = set()
    directory_paths: set[str] = set()
    file_paths: set[str] = set()
    for index, row in enumerate(rows):
        if type(row) is not dict or set(row) != {
            "kind", "path", "mode", "size", "link_count", "depth", "sha256",
        }:
            raise BuildError("runtime manifest row fields are not exact")
        path = row["path"]
        if type(path) is not str:
            raise BuildError("runtime manifest path is not an exact string")
        path_bytes = path.encode("ascii", "strict")
        if _runtime_manifest_path(path_bytes) != path:
            raise BuildError("runtime manifest path is not canonical")
        if previous is not None and path_bytes <= previous:
            raise BuildError("runtime manifest rows are not canonically ordered")
        previous = path_bytes
        if path.casefold() in folded:
            raise BuildError("runtime manifest paths collide under case folding")
        folded.add(path.casefold())
        depth = len(PurePosixPath(path).parts)
        if type(row["depth"]) is not int or row["depth"] != depth:
            raise BuildError("runtime manifest row depth is not exact")
        parent = PurePosixPath(path).parent.as_posix()
        if parent != "." and parent not in directory_paths:
            raise BuildError("runtime manifest row parent directory is absent")
        kind = row["kind"]
        digest = row["sha256"]
        if type(digest) is not bytes or len(digest) != 32:
            raise BuildError("runtime manifest row digest is not exact")
        if kind == RUNTIME_PACKAGE_MANIFEST_V2_DIRECTORY:
            if (
                row["mode"] != 0o500 or row["size"] != 0
                or row["link_count"] != 0 or any(digest)
            ):
                raise BuildError("runtime manifest directory identity is invalid")
            directory_paths.add(path)
            directories += 1
        elif kind == RUNTIME_PACKAGE_MANIFEST_V2_FILE:
            if (
                row["mode"] != 0o400 or row["link_count"] != 1
                or type(row["size"]) is not int
                or not 0 <= row["size"] <= RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES
            ):
                raise BuildError("runtime manifest file identity is invalid")
            file_paths.add(path)
            files += 1
            total_file_bytes += row["size"]
            if total_file_bytes > RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES:
                raise BuildError("runtime manifest byte census exceeds its bound")
        else:
            raise BuildError("runtime manifest row kind is invalid")
        offset = index * RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE
        struct.pack_into(
            ">HHIQIHH", row_region, offset,
            kind, len(path_bytes), row["mode"], row["size"],
            row["link_count"], depth, 0,
        )
        row_region[offset + 24:offset + 56] = digest
        row_region[offset + 56:offset + 56 + len(path_bytes)] = path_bytes
    if set(RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES) - file_paths:
        raise BuildError("runtime manifest required entrypoints are absent")

    external_binding = _runtime_manifest_binding(bindings)
    total_size = (
        RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE
        + RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE + len(row_region)
        + RUNTIME_PACKAGE_MANIFEST_V2_TRAILER_SIZE
    )
    header = bytearray(RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE)
    header[0:8] = RUNTIME_PACKAGE_MANIFEST_V2_MAGIC
    struct.pack_into(
        ">HHIIIIIQQIHHHHI", header, 8,
        RUNTIME_PACKAGE_MANIFEST_V2_VERSION,
        RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE,
        total_size,
        RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE,
        len(rows), directories, files,
        total_file_bytes,
        RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES,
        RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES,
        RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES,
        RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH,
        len(RUNTIME_PACKAGE_MANIFEST_V2_ROOT.encode("ascii")),
        len(RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES),
        RUNTIME_PACKAGE_MANIFEST_V2_FLAGS,
    )
    struct.pack_into(
        ">II", header, 64,
        RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE,
        len(RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS),
    )
    census_digest = hashlib.sha256(row_region).digest()
    header[96:128] = census_digest
    root = RUNTIME_PACKAGE_MANIFEST_V2_ROOT.encode("ascii")
    header[160:160 + len(root)] = root
    tree_digest = hashlib.sha256(
        b"plamen.runtime-package.tree.v2\0" + root
        + struct.pack(">IIIQ", len(rows), directories, files, total_file_bytes)
        + external_binding + row_region
    ).digest()
    header[128:160] = tree_digest
    manifest = header + external_binding + row_region
    manifest.extend(hashlib.sha256(manifest).digest())
    return bytes(manifest)


def render_runtime_package_manifest_v2(
    runtime_root: Path, *, bindings: dict[str, Any],
) -> bytes:
    """Render deterministic role-8 bytes without granting install authority.

    The native installer must retain, publish and independently revalidate the
    returned bytes and every input identity.  Rendering is content derivation,
    never an authorization decision.
    """

    return _runtime_manifest_encode(_runtime_manifest_scan(runtime_root), bindings)


def decode_runtime_package_manifest_v2(
    manifest: bytes,
) -> dict[str, Any]:
    """Strictly decode and semantically validate a role-8 manifest."""

    if type(manifest) is not bytes or len(manifest) < (
        RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE
        + RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
        + RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE
        + RUNTIME_PACKAGE_MANIFEST_V2_TRAILER_SIZE
    ):
        raise BuildError("runtime manifest size is outside its bound")
    if manifest[:8] != RUNTIME_PACKAGE_MANIFEST_V2_MAGIC:
        raise BuildError("runtime manifest magic is invalid")
    values = struct.unpack_from(">HHIIIIIQQIHHHHI", manifest, 8)
    (
        version, header_size, total_size, row_size, entry_count,
        directory_count, file_count, total_file_bytes, max_file_bytes,
        max_entries, max_path_bytes, max_depth, root_length,
        required_file_count, flags,
    ) = values
    if (
        version != RUNTIME_PACKAGE_MANIFEST_V2_VERSION
        or header_size != RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE
        or row_size != RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE
        or max_file_bytes != RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES
        or max_entries != RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES
        or max_path_bytes != RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES
        or max_depth != RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH
        or required_file_count != len(RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES)
        or flags != RUNTIME_PACKAGE_MANIFEST_V2_FLAGS
        or not 1 <= entry_count <= RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES
    ):
        raise BuildError("runtime manifest header constants are not exact")
    expected_size = (
        header_size + RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
        + entry_count * row_size + RUNTIME_PACKAGE_MANIFEST_V2_TRAILER_SIZE
    )
    if total_size != len(manifest) or total_size != expected_size:
        raise BuildError("runtime manifest total size is not exact")
    if not secrets.compare_digest(
        manifest[-32:], hashlib.sha256(manifest[:-32]).digest()
    ):
        raise BuildError("runtime manifest trailer digest is invalid")
    binding_size, binding_digest_count = struct.unpack_from(">II", manifest, 64)
    if (
        binding_size != RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
        or binding_digest_count != len(RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS)
        or any(manifest[72:96]) or any(manifest[224:256])
    ):
        raise BuildError("runtime manifest header padding is nonzero")
    root_slot = manifest[160:224]
    if (
        root_length != len(RUNTIME_PACKAGE_MANIFEST_V2_ROOT.encode("ascii"))
        or root_slot[:root_length] != RUNTIME_PACKAGE_MANIFEST_V2_ROOT.encode("ascii")
        or any(root_slot[root_length:])
    ):
        raise BuildError("runtime manifest root is not exact")
    binding_raw = manifest[header_size:header_size + binding_size]
    bindings = _runtime_manifest_decode_binding(binding_raw)
    row_region = manifest[header_size + binding_size:-32]
    if not secrets.compare_digest(manifest[96:128], hashlib.sha256(row_region).digest()):
        raise BuildError("runtime manifest census digest is invalid")

    rows: list[dict[str, Any]] = []
    for index in range(entry_count):
        offset = index * row_size
        kind, path_length, mode, size, link_count, depth, reserved = (
            struct.unpack_from(">HHIQIHH", row_region, offset)
        )
        if reserved != 0 or path_length < 1 or path_length > max_path_bytes:
            raise BuildError("runtime manifest row header is invalid")
        digest = row_region[offset + 24:offset + 56]
        path_slot = row_region[offset + 56:offset + 568]
        if any(path_slot[path_length:]) or any(row_region[offset + 568:offset + 640]):
            raise BuildError("runtime manifest row padding is nonzero")
        path = _runtime_manifest_path(path_slot[:path_length])
        rows.append({
            "kind": kind, "path": path, "mode": mode, "size": size,
            "link_count": link_count, "depth": depth, "sha256": bytes(digest),
        })
    canonical = _runtime_manifest_encode(rows, bindings)
    if not secrets.compare_digest(canonical, manifest):
        raise BuildError("runtime manifest semantic census is not exact")
    calculated_tree = hashlib.sha256(
        b"plamen.runtime-package.tree.v2\0"
        + RUNTIME_PACKAGE_MANIFEST_V2_ROOT.encode("ascii")
        + struct.pack(
            ">IIIQ", entry_count, directory_count, file_count, total_file_bytes
        )
        + binding_raw + row_region
    ).digest()
    if not secrets.compare_digest(manifest[128:160], calculated_tree):
        raise BuildError("runtime manifest tree digest is invalid")
    return {
        "schema": "plamen.runtime-package-manifest.v2",
        "root": RUNTIME_PACKAGE_MANIFEST_V2_ROOT,
        "entry_count": entry_count,
        "directory_count": directory_count,
        "file_count": file_count,
        "total_file_bytes": total_file_bytes,
        "census_sha256": manifest[96:128].hex(),
        "tree_sha256": manifest[128:160].hex(),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "external_bindings": bindings,
        "rows": [
            {**row, "sha256": row["sha256"].hex()} for row in rows
        ],
    }


def validate_runtime_package_manifest_v2(
    runtime_root: Path, manifest: bytes,
) -> dict[str, Any]:
    """Re-census a retained tree and compare every manifest byte."""

    decoded = decode_runtime_package_manifest_v2(manifest)
    observed = render_runtime_package_manifest_v2(
        runtime_root, bindings=decoded["external_bindings"]
    )
    if not secrets.compare_digest(observed, manifest):
        raise BuildError("runtime package differs from its exact manifest census")
    return decoded


# Compatibility aliases keep older focused tests visibly non-authoritative.
# The underlying renderer/decoder likewise make no install or publication
# decision; only the future native retained-FD transaction may do that.
TEST_ONLY_build_runtime_package_manifest_v2 = (
    render_runtime_package_manifest_v2
)
TEST_ONLY_decode_runtime_package_manifest_v2 = (
    decode_runtime_package_manifest_v2
)
TEST_ONLY_validate_runtime_package_manifest_v2 = (
    validate_runtime_package_manifest_v2
)


def _sha256_fd(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise BuildError("retained file was truncated while hashing")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise BuildError("retained file grew while hashing")
    return digest.hexdigest()


def _sha256_prefix_fd(descriptor: int, size: int) -> str:
    """Hash exactly one retained prefix while permitting a bound footer."""

    if type(size) is not int or size < 0:
        raise BuildError("retained prefix size differs")
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise BuildError("retained prefix was truncated while hashing")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _identity(info: os.stat_result, sha256: str) -> dict[str, Any]:
    return {
        "device": int(info.st_dev), "inode": int(info.st_ino),
        "size": int(info.st_size), "mode": stat.S_IMODE(info.st_mode),
        "uid": int(info.st_uid), "gid": int(info.st_gid),
        "nlink": int(info.st_nlink), "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns), "sha256": sha256,
        "flags": int(getattr(info, "st_flags", 0)),
    }


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_uid", "st_gid",
              "st_nlink", "st_mtime_ns", "st_ctime_ns")
    return (
        all(getattr(left, key) == getattr(right, key) for key in fields)
        and getattr(left, "st_flags", 0) == getattr(right, "st_flags", 0)
    )


def _directory_anchor(info: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISDIR(info.st_mode):
        raise BuildError("directory authority was replaced by a non-directory")
    return (
        int(info.st_dev), int(info.st_ino), stat.S_IMODE(info.st_mode),
        int(info.st_uid), int(info.st_gid),
    )


def _open_retained_regular(path: Path, label: str) -> tuple[int, Path, dict[str, Any]]:
    try:
        resolved = path.resolve(strict=True)
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise BuildError(f"{label} cannot be retained without following a link") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1:
            raise BuildError(f"{label} is not a non-empty regular file")
        digest = _sha256_fd(descriptor, before.st_size)
        after = os.fstat(descriptor)
        if not _same_stat(before, after):
            raise BuildError(f"{label} changed during admission")
        return descriptor, resolved, {"path": str(resolved), **_identity(after, digest)}
    except BaseException:
        os.close(descriptor)
        raise


def _writable_by_current_process(info: os.stat_result) -> bool:
    if os.geteuid() == 0:
        return True
    if info.st_uid == os.geteuid() and info.st_mode & stat.S_IWUSR:
        return True
    groups = set(os.getgroups()) | {os.getegid()}
    if info.st_gid in groups and info.st_mode & stat.S_IWGRP:
        return True
    return bool(info.st_mode & stat.S_IWOTH)


def _native_executable(header: bytes) -> bool:
    if header.startswith(b"\x7fELF"):
        return True
    return header[:4] in {
        b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    }


def _resolve_compiler_path(
    token: str, environment: MappingProxyType,
) -> tuple[Path, dict[str, Any]]:
    if sys.platform != "darwin":
        found = shutil.which(token, path=environment["PATH"])
        if found is None:
            raise BuildError("CPython compiler executable is unavailable")
        return Path(found), {
            "kind": "CLOSED_PATH_LOOKUP", "configured_token": token,
            "search_path": environment["PATH"],
        }
    if token not in {"clang", "cc", "/usr/bin/clang", "/usr/bin/cc"}:
        raise BuildError("Darwin compiler token is not in the fixed native allowlist")
    resolver_fd, resolver, resolver_identity = _open_retained_regular(
        Path("/usr/bin/xcrun"), "Darwin toolchain resolver"
    )
    try:
        executable, authority = _executable_authority(resolver_fd, resolver)
        completed = subprocess.run(
            (str(resolver), "--find", Path(token).name),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=environment, close_fds=True,
            pass_fds=(resolver_fd,), executable=executable,
            check=False, timeout=10,
        )
        if completed.returncode != 0 or not 1 <= len(completed.stdout) <= 4096:
            raise BuildError("Darwin compiler resolution failed")
        try:
            rendered = completed.stdout.decode("utf-8", "strict").strip()
        except UnicodeError as exc:
            raise BuildError("Darwin compiler resolution was not UTF-8") from exc
        resolved = Path(rendered).resolve(strict=True)
        return resolved, {
            "kind": "DARWIN_SIP_XCRUN_EXACT_NATIVE_TOOL",
            "configured_token": token,
            "command_template": ["{PINNED_XCRUN}", "--find", Path(token).name],
            "resolver": resolver_identity,
            "resolver_execution_authority": authority,
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        }
    finally:
        os.close(resolver_fd)


def _open_compiler(
    environment: MappingProxyType,
) -> tuple[int, Path, tuple[str, ...], dict[str, Any], dict[str, Any]]:
    configured = sysconfig.get_config_var("CC")
    if not isinstance(configured, str) or not configured.strip():
        raise BuildError("CPython does not declare a compiler")
    try:
        tokens = shlex.split(configured, posix=True)
    except ValueError as exc:
        raise BuildError("CPython compiler declaration is malformed") from exc
    if not tokens or len(tokens) > 4 or any(len(item) > 128 or "\x00" in item for item in tokens):
        raise BuildError("CPython compiler declaration is unbounded")
    suffix = tuple(tokens[1:])
    if suffix not in {(), ("-pthread",), ("-m64",), ("-m32",),
                      ("-arch", "arm64"), ("-arch", "x86_64")}:
        raise BuildError("CPython compiler suffix is not in the fixed safe allowlist")
    compiler_path, resolution = _resolve_compiler_path(tokens[0], environment)
    descriptor, resolved, identity = _open_retained_regular(compiler_path, "compiler")
    info = os.fstat(descriptor)
    try:
        if not stat.S_IMODE(info.st_mode) & 0o111 or _writable_by_current_process(info):
            raise BuildError("compiler executable is not controlled by an immutable authority")
        if not _native_executable(os.pread(descriptor, 8, 0)):
            raise BuildError("compiler wrappers/scripts are forbidden")
        return descriptor, resolved, suffix, identity, resolution
    except BaseException:
        os.close(descriptor)
        raise


def _fd_path(descriptor: int) -> str:
    return f"/dev/fd/{descriptor}" if sys.platform == "darwin" else f"/proc/self/fd/{descriptor}"


def _executable_authority(descriptor: int, path: Path) -> tuple[str, str]:
    if sys.platform == "linux":
        return _fd_path(descriptor), "LINUX_RETAINED_EXECUTABLE_FD"
    restricted = getattr(stat, "SF_RESTRICTED", _DARWIN_SF_RESTRICTED)
    info = os.fstat(descriptor)
    if restricted and info.st_uid == 0 and info.st_flags & restricted:
        return str(path), "DARWIN_SIP_RESTRICTED_PATH_WITH_RETAINED_FD_REVALIDATION"
    command_line_tools = Path("/Library/Developer/CommandLineTools").resolve(strict=True)
    try:
        path.resolve(strict=True).relative_to(command_line_tools)
    except ValueError as exc:
        raise BuildError("Darwin executable lacks a supported immutable authority") from exc
    if info.st_uid != 0 or _writable_by_current_process(info):
        raise BuildError("Darwin toolchain executable is not root-owned and non-writable")
    return str(path), "DARWIN_ROOT_OWNED_CLT_PATH_WITH_RETAINED_FD_REVALIDATION"


def _run_probe(
    compiler_fd: int, compiler: Path, suffix: tuple[str, ...],
    arguments: list[str], environment: MappingProxyType,
) -> bytes:
    executable, _authority = _executable_authority(compiler_fd, compiler)
    try:
        completed = subprocess.run(
            [str(compiler), *suffix, *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=environment, close_fds=True, pass_fds=(compiler_fd,),
            executable=executable, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("compiler identity probe failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > MAX_COMPILER_OUTPUT_BYTES:
        raise BuildError("compiler identity probe was not bounded and successful")
    return completed.stdout


def _safe_relative(path: str) -> str:
    rendered = PurePosixPath(path).as_posix()
    if rendered in {"", ".", ".."} or rendered.startswith("/") or any(
        part in {"", ".", ".."} or _SAFE_COMPONENT.fullmatch(part) is None
        for part in PurePosixPath(rendered).parts
    ):
        raise BuildError("header tree contains a non-canonical path")
    return rendered


def _tree_rows(root: Path, label: str) -> tuple[Path, list[dict[str, Any]]]:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise BuildError(f"{label} root is unavailable") from exc
    if not resolved.is_dir():
        raise BuildError(f"{label} root is not a directory")
    rows: list[dict[str, Any]] = []
    folded: set[str] = set()
    total = 0
    for directory, names, files in os.walk(resolved, topdown=True, followlinks=False):
        names.sort(); files.sort()
        directory_path = Path(directory)
        for name in list(names):
            candidate = directory_path / name
            if candidate.is_symlink():
                raise BuildError(f"{label} contains a directory symlink")
        for name in files:
            candidate = directory_path / name
            if candidate.is_symlink():
                raise BuildError(f"{label} contains a file symlink")
            relative = _safe_relative(candidate.relative_to(resolved).as_posix())
            if relative.casefold() in folded:
                raise BuildError(f"{label} contains case-colliding paths")
            folded.add(relative.casefold())
            descriptor, opened, identity = _open_retained_regular(candidate, f"{label} file")
            os.close(descriptor)
            if opened != candidate:
                raise BuildError(f"{label} file resolved through an alias")
            total += identity["size"]
            if len(rows) >= MAX_SNAPSHOT_FILES or total > MAX_SNAPSHOT_BYTES:
                raise BuildError(f"{label} exceeds its snapshot bound")
            rows.append({"path": relative, **{key: identity[key] for key in (
                "size", "mode", "uid", "gid", "sha256")}})
    if not rows:
        raise BuildError(f"{label} is empty")
    return resolved, rows


def _tree_commitment(root: Path, label: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    resolved, rows = _tree_rows(root, label)
    return {
        "path": str(resolved), "file_count": len(rows),
        "total_bytes": sum(item["size"] for item in rows),
        "census_sha256": hashlib.sha256(_canonical_json_bytes(rows)).hexdigest(),
    }, rows


def _mkdir_new(parent_fd: int, name: str) -> int:
    if _SAFE_COMPONENT.fullmatch(name) is None:
        raise BuildError("private directory name is malformed")
    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    info = os.fstat(descriptor)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor)
        raise BuildError("private directory identity is unsafe")
    return descriptor


def _open_directory_nofollow(path: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(path)))
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:]:
            if component in {"", ".", ".."}:
                raise BuildError("staging root is not canonical")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor); raise


def _require_private_root(path: Path) -> tuple[Path, int]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BuildError("staging root cannot be resolved") from exc
    if absolute != resolved:
        raise BuildError("staging root path or an ancestor is a symlink alias")
    descriptor = _open_directory_nofollow(resolved)
    info = os.fstat(descriptor)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor)
        raise BuildError("staging root must be owned by this user with exact mode 0700")
    return resolved, descriptor


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise BuildError("short write while staging build input")
        view = view[count:]


def _make_immutable(descriptor: int) -> str:
    os.fchmod(descriptor, 0o400)
    if sys.platform == "darwin":
        immutable = getattr(stat, "UF_IMMUTABLE", None)
        if immutable is None or not hasattr(os, "chflags"):
            raise BuildError("Darwin immutable snapshot authority is unavailable")
        os.chflags(f"/dev/fd/{descriptor}", immutable)
        if not os.fstat(descriptor).st_flags & immutable:
            raise BuildError("Darwin immutable snapshot flag was not retained")
        return "DARWIN_UF_IMMUTABLE_RETAINED_FD"
    if fcntl is None or not all(
        hasattr(fcntl, name)
        for name in ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE",
                     "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
    ):
        raise BuildError("Linux sealed-memory snapshot authority is unavailable")
    seals = (
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    )
    try:
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        observed = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    except OSError as exc:
        raise BuildError("Linux source snapshot could not be kernel-sealed") from exc
    if observed & seals != seals:
        raise BuildError("Linux source snapshot seal set is incomplete")
    return "LINUX_MEMFD_FULLY_SEALED_RETAINED_FD"


def _clear_immutable(descriptor: int) -> None:
    if sys.platform == "darwin" and hasattr(os, "chflags"):
        os.chflags(f"/dev/fd/{descriptor}", 0)


def _snapshot_source(source_fd: int, identity: dict[str, Any], workspace_fd: int, name: str) -> tuple[int, dict[str, Any]]:
    if sys.platform == "linux":
        if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
            raise BuildError("Linux memfd snapshot authority is unavailable")
        descriptor = os.memfd_create(
            "plamen-native-source",
            flags=getattr(os, "MFD_CLOEXEC", 0) | os.MFD_ALLOW_SEALING,
        )
    else:
        descriptor = os.open(
            name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=workspace_fd,
        )
    try:
        offset = 0
        while offset < identity["size"]:
            chunk = os.pread(source_fd, min(1024 * 1024, identity["size"] - offset), offset)
            if not chunk:
                raise BuildError("source changed while snapshotting")
            _write_all(descriptor, chunk); offset += len(chunk)
        os.fsync(descriptor)
        if sys.platform == "darwin":
            os.fchmod(descriptor, 0o400)
            readonly = os.open(
                name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=workspace_fd,
            )
            os.close(descriptor)
            descriptor = readonly
            os.unlink(name, dir_fd=workspace_fd)
            os.fsync(workspace_fd)
            method = "DARWIN_UNLINKED_READONLY_RETAINED_FD_NO_WRITER"
        else:
            method = _make_immutable(descriptor)
        info = os.fstat(descriptor)
        digest = _sha256_fd(descriptor, info.st_size)
        if digest != identity["sha256"] or info.st_size != identity["size"]:
            raise BuildError("source snapshot does not equal admitted source")
        return descriptor, {**_identity(info, digest), "sealing": method}
    except BaseException:
        try: _clear_immutable(descriptor)
        except OSError: pass
        os.close(descriptor); raise


def _remove_directory_contents(directory_fd: int) -> None:
    for name in sorted(os.listdir(directory_fd)):
        if _SAFE_COMPONENT.fullmatch(name) is None:
            raise BuildError("private workspace contains a malformed entry")
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                admitted = _directory_anchor(os.fstat(child_fd))
                _remove_directory_contents(child_fd)
                if _directory_anchor(os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )) != admitted:
                    raise BuildError("workspace directory changed during cleanup")
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def _remove_workspace_at(root_fd: int, name: str, workspace_fd: int) -> None:
    """Descriptor-relative cleanup that never follows a substituted workspace."""

    if not name.startswith("workspace-") or len(name) != 74:
        raise BuildError("refusing to remove a non-workspace path")
    admitted = _directory_anchor(os.fstat(workspace_fd))
    if _directory_anchor(os.stat(
        name, dir_fd=root_fd, follow_symlinks=False
    )) != admitted:
        raise BuildError("workspace name no longer identifies its retained directory")
    _remove_directory_contents(workspace_fd)
    os.fsync(workspace_fd)
    if _directory_anchor(os.stat(
        name, dir_fd=root_fd, follow_symlinks=False
    )) != admitted:
        raise BuildError("workspace name changed before removal")
    os.rmdir(name, dir_fd=root_fd)
    os.fsync(root_fd)


def _sdk_binding(
    environment: MappingProxyType,
) -> tuple[dict[str, Any], list[str], list[tuple[int, dict[str, Any]]]]:
    if sys.platform != "darwin":
        return {"kind": "LINUX_SYSTEM_TOOLCHAIN", "sysroot": ""}, [], []
    xcrun = Path("/usr/bin/xcrun")
    xfd, xresolved, xidentity = _open_retained_regular(xcrun, "xcrun")
    try:
        if _writable_by_current_process(os.fstat(xfd)) or not _native_executable(os.pread(xfd, 8, 0)):
            raise BuildError("SDK resolver is not controlled by an immutable authority")
        executable, execution_authority = _executable_authority(xfd, xresolved)
        completed = subprocess.run(
            [str(xresolved), "--show-sdk-path"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=environment,
            close_fds=True, pass_fds=(xfd,), executable=executable,
            check=False, timeout=10,
        )
        if completed.returncode != 0 or len(completed.stdout) > 4096:
            raise BuildError("SDK resolver failed")
        sdk = Path(completed.stdout.decode("utf-8", "strict").strip()).resolve(strict=True)
        sdk_topology = _require_root_owned_nonwritable_ancestry(
            sdk, "SDK root"
        )
        settings = sdk / "SDKSettings.json"
        sfd, sresolved, sidentity = _open_retained_regular(settings, "SDK settings")
        try:
            if _writable_by_current_process(os.fstat(sfd)):
                raise BuildError("SDK settings are writable by the current process")
            settings_topology = _require_root_owned_nonwritable_ancestry(
                sresolved, "SDK settings"
            )
        except BaseException:
            os.close(sfd)
            raise
        root_info = sdk.stat()
        binding = {
            "kind": "DARWIN_XCRUN_PINNED_SDK", "sysroot": str(sdk),
            "root": {"device": root_info.st_dev, "inode": root_info.st_ino,
                     "mode": stat.S_IMODE(root_info.st_mode), "uid": root_info.st_uid,
                     "gid": root_info.st_gid},
            "settings": sidentity, "resolver": xidentity,
            "root_topology": sdk_topology,
            "settings_topology": settings_topology,
            "resolver_execution_authority": execution_authority,
        }
        return binding, ["-isysroot", str(sdk)], [(sfd, sidentity)]
    finally:
        os.close(xfd)


def _run_macho_inspector(
    inspector_fd: int,
    inspector: Path,
    inspector_executable: str,
    target_fd: int,
    option: str,
    environment: MappingProxyType,
) -> bytes:
    completed = subprocess.run(
        (str(inspector), option, _fd_path(target_fd)),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=environment, close_fds=True,
        pass_fds=(inspector_fd, target_fd), executable=inspector_executable,
        check=False, timeout=10,
    )
    if completed.returncode != 0 or len(completed.stdout) > MAX_COMPILER_OUTPUT_BYTES:
        raise BuildError("Mach-O transitive load-command inspection failed")
    return completed.stdout


def _canonical_macho_output(raw: bytes, target_fd: int) -> bytes:
    descriptor_path = _fd_path(target_fd).encode("ascii")
    if descriptor_path not in raw:
        raise BuildError("Mach-O inspector did not identify the retained target")
    return raw.replace(descriptor_path, b"{RETAINED_TARGET_FD}")


def _macho_rpaths(raw: bytes, executable_dir: Path, loader_dir: Path) -> list[Path]:
    """Extract and deterministically expand every LC_RPATH in all slices."""

    decoded = raw.decode("utf-8", "strict").splitlines()
    rendered: list[Path] = []
    for number, line in enumerate(decoded):
        if line.strip() != "cmd LC_RPATH":
            continue
        if number + 2 >= len(decoded):
            raise BuildError("Mach-O LC_RPATH record is truncated")
        match = re.fullmatch(r"\s*path (.+) \(offset [0-9]+\)", decoded[number + 2])
        if match is None:
            raise BuildError("Mach-O LC_RPATH record is not canonical")
        value = match.group(1)
        if value.startswith("@executable_path/"):
            candidate = executable_dir / value.removeprefix("@executable_path/")
        elif value.startswith("@loader_path/"):
            candidate = loader_dir / value.removeprefix("@loader_path/")
        elif value.startswith("/"):
            candidate = Path(value)
        else:
            raise BuildError("Mach-O LC_RPATH uses an unsupported token")
        resolved = candidate.resolve(strict=True)
        if resolved not in rendered:
            rendered.append(resolved)
    return rendered


def _resolve_macho_dependency(
    load_path: str,
    *,
    executable_dir: Path,
    loader_dir: Path,
    rpaths: list[Path],
) -> Path | None:
    if load_path.startswith("/"):
        candidate = Path(load_path)
        return candidate.resolve(strict=True) if candidate.exists() else None
    if load_path.startswith("@loader_path/"):
        candidate = loader_dir / load_path.removeprefix("@loader_path/")
        return candidate.resolve(strict=True)
    if load_path.startswith("@executable_path/"):
        candidate = executable_dir / load_path.removeprefix("@executable_path/")
        return candidate.resolve(strict=True)
    if load_path.startswith("@rpath/"):
        suffix = load_path.removeprefix("@rpath/")
        matches = [(root / suffix).resolve(strict=True) for root in rpaths if (root / suffix).exists()]
        if len(set(matches)) != 1:
            raise BuildError("Mach-O @rpath dependency did not resolve uniquely")
        return matches[0]
    raise BuildError("Mach-O load command uses an unsupported path token")


def _toolchain_dynamic_closure(
    compiler: Path, linker: Path, environment: MappingProxyType,
) -> tuple[dict[str, Any], list[tuple[int, dict[str, Any]]]]:
    if sys.platform != "darwin":
        return ({
            "kind": "LINUX_TRANSITIVE_ELF_LOADER_CLOSURE_PENDING_NATIVE_PROOF",
            "production_build_allowed": False,
        }, [])
    inspector_fd, inspector, inspector_identity = _open_retained_regular(
        Path("/usr/bin/otool"), "Mach-O load-command inspector"
    )
    try:
        executable, authority = _executable_authority(inspector_fd, inspector)
        retained: list[tuple[int, dict[str, Any]]] = [
            (inspector_fd, inspector_identity)
        ]
        inspector_fd = -1
        queue: list[tuple[str, Path, Path]] = [
            ("compiler", compiler, compiler.parent),
            ("linker", linker, linker.parent),
        ]
        seen: set[tuple[str, Path, Path, Path]] = set()
        rows: list[dict[str, Any]] = []
        while queue:
            root_role, target, executable_dir = queue.pop(0)
            target = target.resolve(strict=True)
            context = (root_role, target, executable_dir, target.parent)
            if context in seen:
                continue
            if len(seen) >= MAX_TOOLCHAIN_MEMBERS:
                raise BuildError("Mach-O toolchain closure exceeds its member bound")
            target_fd, opened, target_identity = _open_retained_regular(
                target, "Mach-O toolchain member"
            )
            try:
                target_info = os.fstat(target_fd)
                if _writable_by_current_process(target_info):
                    raise BuildError("Mach-O toolchain member is not immutable-authority owned")
                target_topology = _require_root_owned_nonwritable_ancestry(
                    opened, "Mach-O toolchain member"
                )
                load_commands = _run_macho_inspector(
                    retained[0][0], inspector, executable, target_fd, "-L", environment
                )
                full_commands = _run_macho_inspector(
                    retained[0][0], inspector, executable, target_fd, "-l", environment
                )
                install_names_raw = _run_macho_inspector(
                    retained[0][0], inspector, executable, target_fd, "-D", environment
                )
                install_names = {
                    line.strip()
                    for line in install_names_raw.decode("utf-8", "strict").splitlines()
                    if line.strip() and not line.rstrip().endswith(":")
                }
                rpaths = _macho_rpaths(full_commands, executable_dir, opened.parent)
                dependencies: list[dict[str, Any]] = []
                for line in load_commands.decode("utf-8", "strict").splitlines():
                    # Fat Mach-O slice headings are not indented; dependencies are.
                    if not line.startswith((" ", "\t")):
                        continue
                    rendered = line.strip()
                    if not rendered:
                        continue
                    load_path = rendered.split(" (compatibility version ", 1)[0]
                    if load_path in install_names:
                        dependencies.append({
                            "load_command": rendered, "kind": "LC_ID_DYLIB",
                        })
                        continue
                    candidate = _resolve_macho_dependency(
                        load_path, executable_dir=executable_dir,
                        loader_dir=opened.parent, rpaths=rpaths,
                    )
                    if candidate is None:
                        if not load_path.startswith(("/usr/lib/", "/System/Library/")):
                            raise BuildError("non-system Mach-O dependency is absent from disk")
                        dependencies.append({
                            "load_command": rendered,
                            "identity": "DARWIN_SIP_DYLD_SHARED_CACHE_ENTRY",
                        })
                        continue
                    dependency_fd, dependency_path, dependency_identity = _open_retained_regular(
                        candidate, "Mach-O dependency"
                    )
                    try:
                        if _writable_by_current_process(os.fstat(dependency_fd)):
                            raise BuildError("Mach-O dependency is not immutable-authority owned")
                        dependency_topology = _require_root_owned_nonwritable_ancestry(
                            dependency_path, "Mach-O dependency"
                        )
                    finally:
                        os.close(dependency_fd)
                    dependencies.append({
                        "load_command": rendered, "resolved_path": str(dependency_path),
                        "identity": dependency_identity,
                        "topology": dependency_topology,
                    })
                    dependency_context = (
                        root_role, dependency_path, executable_dir,
                        dependency_path.parent,
                    )
                    if dependency_context not in seen:
                        queue.append((root_role, dependency_path, executable_dir))
                rows.append({
                    "root_role": root_role, "target": str(opened),
                    "executable_directory": str(executable_dir),
                    "loader_directory": str(opened.parent),
                    "target_identity": target_identity,
                    "target_topology": target_topology,
                    "load_commands_sha256": hashlib.sha256(
                        _canonical_macho_output(load_commands, target_fd)
                    ).hexdigest(),
                    "all_commands_sha256": hashlib.sha256(
                        _canonical_macho_output(full_commands, target_fd)
                    ).hexdigest(),
                    "install_names_sha256": hashlib.sha256(
                        _canonical_macho_output(install_names_raw, target_fd)
                    ).hexdigest(),
                    "install_names": sorted(install_names),
                    "rpaths": [str(path) for path in rpaths],
                    "dependencies": dependencies,
                })
                retained.append((target_fd, target_identity))
                target_fd = -1
                seen.add(context)
            finally:
                if target_fd >= 0:
                    os.close(target_fd)
        rows.sort(key=lambda item: (item["root_role"], item["target"]))
        return ({
            "kind": "DARWIN_SIP_MACHO_LOAD_COMMAND_CLOSURE_V1",
            "production_build_allowed": True,
            "inspector": inspector_identity,
            "inspector_execution_authority": authority,
            "inspector_command_templates": [
                ["{PINNED_OTOOL}", option, "{RETAINED_MEMBER_FD}"]
                for option in ("-L", "-l", "-D")
            ],
            "os_build": os.uname().release,
            "members": rows,
        }, retained)
    except BaseException:
        for descriptor, _identity_row in locals().get("retained", []):
            os.close(descriptor)
        raise
    finally:
        if inspector_fd >= 0:
            os.close(inspector_fd)


def _metadata(
    test_only: bool, *, test_production_shape: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(test_only) is not bool or type(test_production_shape) is not bool:
        raise BuildError("build variants require exact bool values")
    if not test_only and not test_production_shape:
        raise BuildError(
            "production build requires an exec-time authenticated native builder"
        )
    if test_only and test_production_shape:
        raise BuildError("build variants are mutually exclusive")
    with ExitStack() as resources:
        result = _metadata_inner(test_only, test_production_shape, resources)
        resources.pop_all()
        return result


def _metadata_inner(
    test_only: bool, test_production_shape: bool, resources: ExitStack,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if sys.implementation.name != "cpython" or sys.version_info[:2] not in SUPPORTED_CPYTHON_ABIS:
        raise BuildError("only exact supported CPython ABIs are accepted")
    if sys.platform not in SUPPORTED_PLATFORMS:
        raise BuildError("only macOS and Linux are supported")
    soabi = sysconfig.get_config_var("SOABI"); suffix = sysconfig.get_config_var("EXT_SUFFIX")
    include = sysconfig.get_path("include"); platinclude = sysconfig.get_path("platinclude")
    if not all(isinstance(item, str) and item for item in (soabi, suffix, include, platinclude)):
        raise BuildError("CPython ABI metadata is incomplete")
    if (
        suffix not in __import__("importlib.machinery").machinery.EXTENSION_SUFFIXES
        or "/" in suffix or "\\" in suffix or "\x00" in suffix
        or len(suffix.encode("ascii", "strict")) > 200
    ):
        raise BuildError("CPython extension suffix is not canonical")
    environment = dict(_CLOSED_ENV)
    environment_proxy = MappingProxyType(environment)
    (
        compiler_fd, compiler, compiler_suffix, compiler_identity,
        compiler_resolution,
    ) = _open_compiler(environment_proxy)
    resources.callback(os.close, compiler_fd)
    compiler_topology = _require_root_owned_nonwritable_ancestry(
        compiler, "compiler"
    )
    source_fd, source, source_identity = _open_retained_regular(SOURCE, "native source")
    resources.callback(os.close, source_fd)
    protocol_fd, protocol_source, protocol_identity = _open_retained_regular(
        PROTOCOL_SOURCE, "native broker protocol source"
    )
    resources.callback(os.close, protocol_fd)
    receipt_fd = -1
    receipt_source: Path | None = None
    receipt_identity: dict[str, Any] | None = None
    if sys.platform == "darwin":
        receipt_fd, receipt_source, receipt_identity = _open_retained_regular(
            DARWIN_RECEIPT_SOURCE, "Darwin install receipt source"
        )
        resources.callback(os.close, receipt_fd)
    native_header_commitment, native_header_rows = _tree_commitment(
        NATIVE_HEADER_ROOT, "native broker ABI headers"
    )
    include_roots: list[tuple[Path, dict[str, Any], list[dict[str, Any]]]] = []
    seen: set[Path] = set()
    for number, raw in enumerate((include, platinclude)):
        commitment, rows = _tree_commitment(Path(raw), f"Python include {number}")
        root = Path(commitment["path"])
        if root not in seen:
            seen.add(root); include_roots.append((root, commitment, rows))
    version = _run_probe(
        compiler_fd, compiler, compiler_suffix, ["--version"], environment_proxy
    )
    resource_argument = "-print-resource-dir" if "clang" in compiler.name else "-print-file-name=include"
    resource_raw = _run_probe(
        compiler_fd, compiler, compiler_suffix, [resource_argument], environment_proxy
    )
    resource_path = Path(resource_raw.decode("utf-8", "strict").strip()).resolve(strict=True)
    resource_topology = _require_root_owned_nonwritable_ancestry(
        resource_path, "compiler resource directory"
    )
    resource_commitment, _ = _tree_commitment(resource_path / "include", "compiler resource headers")
    sdk, sdk_flags, sdk_fds = _sdk_binding(environment_proxy)
    for descriptor, _identity_row in sdk_fds:
        resources.callback(os.close, descriptor)
    linker_raw = _run_probe(
        compiler_fd, compiler, compiler_suffix, ["-print-prog-name=ld"],
        environment_proxy,
    )
    linker_fd, linker, linker_identity = _open_retained_regular(
        Path(linker_raw.decode("utf-8", "strict").strip()), "linker"
    )
    resources.callback(os.close, linker_fd)
    linker_topology = _require_root_owned_nonwritable_ancestry(
        linker, "linker"
    )
    if (
        not stat.S_IMODE(os.fstat(linker_fd).st_mode) & 0o111
        or _writable_by_current_process(os.fstat(linker_fd))
        or not _native_executable(os.pread(linker_fd, 8, 0))
    ):
        raise BuildError("linker is not controlled by an immutable authority")
    module = TEST_ONLY_MODULE if test_only else PRODUCTION_MODULE
    output_name = (
        f"{module}{suffix}" if test_only
        else f"{PRODUCTION_MODULE}_testshape{suffix}"
    )
    logical_include_flags = [
        "-I{NATIVE_EXTENSION_SOURCE_DIRECTORY}",
        "-I{NATIVE_PROTOCOL_SOURCE_DIRECTORY}",
        *(
            ["-I{NATIVE_DARWIN_SOURCE_DIRECTORY}"]
            if receipt_source is not None else []
        ),
        "-I{NATIVE_HEADER_ROOT}",
        *(f"-I{{PYTHON_INCLUDE_{number}}}" for number in range(len(include_roots))),
    ]
    compile_flags = ["-std=c11", "-x", "c", "-fPIC", "-fvisibility=hidden", "-Wall", "-Wextra", "-Werror", *logical_include_flags]
    if sys.platform == "darwin": compile_flags.append("-fblocks")
    if test_only: compile_flags.append("-DPLAMEN_NATIVE_SUPERVISOR_TEST_ONLY=1")
    link_flags = (
        [
            f"--ld-path={linker}", "-bundle", "-undefined", "dynamic_lookup",
            "-framework", "CoreFoundation", "-framework", "Security",
        ]
        if sys.platform == "darwin"
        else [f"-fuse-ld={linker}", "-shared", "-lcrypto"]
    )
    sysconfig_values = {key: sysconfig.get_config_var(key) for key in _SYSCONFIG_KEYS}
    interpreter_fd, _interpreter_path, interpreter_identity = _open_retained_regular(
        Path(sys.executable), "interpreter"
    )
    os.close(interpreter_fd)
    builder_fd, _builder_path, builder_identity = _open_retained_regular(
        Path(__file__), "native builder"
    )
    os.close(builder_fd)
    artifact_inspector_fd, artifact_inspector, artifact_inspector_identity = (
        _open_retained_regular(Path("/usr/bin/nm"), "artifact symbol inspector")
    )
    resources.callback(os.close, artifact_inspector_fd)
    artifact_inspector_executable, artifact_inspector_authority = (
        _executable_authority(artifact_inspector_fd, artifact_inspector)
    )
    toolchain_closure, toolchain_fds = _toolchain_dynamic_closure(
        compiler, linker, environment_proxy
    )
    for descriptor, _identity_row in toolchain_fds:
        resources.callback(os.close, descriptor)
    if toolchain_closure["production_build_allowed"] is not True:
        raise BuildError("transitive native toolchain closure proof is unavailable")
    metadata = {
        "schema": "plamen-native-supervisor-build-v2", "module": module,
        "init_symbol": f"PyInit_{module}", "output_basename": output_name,
        "variant": "TEST_ONLY" if test_only else "TEST_ONLY_PRODUCTION_SHAPE",
        "production_packaging_allowed": False,
        "required_test_only_build": True,
        "platform": sys.platform, "machine": os.uname().machine,
        "python_implementation": sys.implementation.name,
        "python_version": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
        "python_hexversion": sys.hexversion, "python_cache_tag": sys.implementation.cache_tag,
        "soabi": soabi, "extension_suffix": suffix,
        "pointer_bits": 8 * __import__("struct").calcsize("P"),
        "sysconfig": sysconfig_values,
        "interpreter": interpreter_identity,
        "compiler": compiler_identity,
        "compiler_topology": compiler_topology,
        "compiler_resolution": compiler_resolution,
        "compiler_execution_authority": _executable_authority(
            compiler_fd, compiler
        )[1],
        "compiler_argv": [str(compiler), *compiler_suffix],
        "compiler_version_stdout_sha256": hashlib.sha256(version).hexdigest(),
        "source": source_identity,
        "protocol_source": protocol_identity,
        "darwin_receipt_source": receipt_identity,
        "source_snapshot": {"sha256": source_identity["sha256"], "size": source_identity["size"], "mode": 0o400,
                            "sealing": "DARWIN_UNLINKED_READONLY_RETAINED_FD_NO_WRITER" if sys.platform == "darwin" else "LINUX_MEMFD_FULLY_SEALED_RETAINED_FD"},
        "protocol_source_snapshot": {
            "sha256": protocol_identity["sha256"],
            "size": protocol_identity["size"],
            "mode": 0o400,
            "sealing": (
                "DARWIN_UNLINKED_READONLY_RETAINED_FD_NO_WRITER"
                if sys.platform == "darwin"
                else "LINUX_MEMFD_FULLY_SEALED_RETAINED_FD"
            ),
        },
        "darwin_receipt_source_snapshot": (
            {
                "sha256": receipt_identity["sha256"],
                "size": receipt_identity["size"],
                "mode": 0o400,
                "sealing": "DARWIN_UNLINKED_READONLY_RETAINED_FD_NO_WRITER",
            }
            if receipt_identity is not None else None
        ),
        "native_header_tree": native_header_commitment,
        "native_header_rows_sha256": hashlib.sha256(
            _canonical_json_bytes(native_header_rows)
        ).hexdigest(),
        "python_include_trees": [item[1] for item in include_roots],
        "compiler_resource_headers": resource_commitment,
        "compiler_resource_directory": str(resource_path),
        "compiler_resource_topology": resource_topology,
        "linker": linker_identity,
        "linker_topology": linker_topology,
        "toolchain_dynamic_closure": toolchain_closure,
        "test_only_builder_path_observation": builder_identity,
        "builder_execution_authority": (
            "TEST_ONLY_UNAUTHENTICATED_LOADED_PYTHON_CODE"
        ),
        "artifact_symbol_inspector": artifact_inspector_identity,
        "artifact_symbol_inspector_execution_authority": (
            artifact_inspector_authority
        ),
        "artifact_symbol_inspection_template": [
            "{PINNED_NM}", "-gjU", "{RETAINED_ARTIFACT_FD}"
        ],
        "sdk": sdk, "sdk_compile_flags": sdk_flags, "link_flags": link_flags,
        "build_environment": environment,
    }
    state = {"compiler_fd": compiler_fd, "compiler": compiler, "compiler_suffix": compiler_suffix,
             "linker_fd": linker_fd, "linker": linker,
             "source_fd": source_fd, "source_identity": source_identity,
             "protocol_fd": protocol_fd,
             "protocol_identity": protocol_identity,
             "receipt_fd": receipt_fd,
             "receipt_identity": receipt_identity,
             "native_header_root": Path(native_header_commitment["path"]),
             "extension_source_include_root": source.parent,
             "native_protocol_include_root": protocol_source.parent,
             "native_darwin_include_root": (
                 receipt_source.parent if receipt_source is not None else None
             ),
             "include_roots": include_roots, "suffix": suffix,
             "sdk_flags": sdk_flags, "logical_flags": compile_flags,
             "link_flags": tuple(link_flags), "module": module,
             "resource_path": resource_path,
             "sdk_root": Path(sdk["sysroot"]) if sdk["sysroot"] else None,
             "sdk_fds": sdk_fds,
             "toolchain_fds": toolchain_fds,
             "artifact_inspector_fd": artifact_inspector_fd,
             "artifact_inspector": artifact_inspector,
             "artifact_inspector_executable": artifact_inspector_executable,
             "environment": environment_proxy,
             "output_name": output_name}
    return metadata, state


def _write_new_retained(
    directory_fd: int, name: str, content: bytes, mode: int,
) -> tuple[int, dict[str, Any]]:
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode, dir_fd=directory_fd,
    )
    try:
        _write_all(descriptor, content); os.fsync(descriptor)
        retained = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        if not _same_stat(os.fstat(descriptor), os.fstat(retained)):
            os.close(retained)
            raise BuildError("durable file identity changed before writer retirement")
        os.close(descriptor)
        descriptor = -1
        observed = os.fstat(retained)
        digest = _sha256_fd(retained, observed.st_size)
        return retained, _identity(observed, digest)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_fd(descriptor: int, maximum: int, label: str) -> bytes:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > maximum:
        raise BuildError(f"{label} does not satisfy its exact size bound")
    raw = bytearray()
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, info.st_size - offset), offset)
        if not chunk:
            raise BuildError(f"{label} was truncated")
        raw.extend(chunk); offset += len(chunk)
    if os.pread(descriptor, 1, info.st_size):
        raise BuildError(f"{label} grew while being retained")
    return bytes(raw)


_BUILD_MANIFEST_V2_POST_KEY_FIELDS = frozenset({
    "artifact", "artifact_symbol_observation", "build_key_sha256",
    "darwin_receipt_source_snapshot_observed",
    "darwin_receipt_translation_unit_observed",
    "production_packaging_allowlist", "protocol_source_snapshot_observed",
    "source_snapshot_observed", "translation_unit_observed",
})


def validate_published_test_build_v2(
    output_root: Path, result: dict[str, Any],
) -> dict[str, Any]:
    """Reopen and validate every byte of a published TEST_ONLY build result.

    This proves deterministic manifest/artifact construction for tests.  It is
    deliberately named and typed as TEST_ONLY and cannot authorize production
    packaging or turn a pathname into a retained native capability.
    """

    result_fields = {
        "schema", "build_key_sha256", "variant", "module", "artifact_path",
        "artifact_sha256", "manifest_path", "manifest_sha256",
        "path_authority",
    }
    if type(result) is not dict or set(result) != result_fields:
        raise BuildError("published TEST_ONLY build result fields are not exact")
    build_key = result["build_key_sha256"]
    if (
        result["schema"] != "plamen-native-supervisor-build-result-v2"
        or type(build_key) is not str
        or re.fullmatch(r"[0-9a-f]{64}", build_key) is None
        or result["path_authority"]
        != "TEST_ONLY_FINAL_DESCRIPTOR_RELATIVE_OBSERVATION"
    ):
        raise BuildError("published TEST_ONLY build result header differs")
    root_path, root_fd = _require_private_root(output_root)
    build_fd = manifest_fd = artifact_fd = -1
    try:
        build_fd = os.open(
            build_key,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        build_info = os.fstat(build_fd)
        if (
            build_info.st_uid != os.geteuid()
            or stat.S_IMODE(build_info.st_mode) != 0o700
        ):
            raise BuildError("published TEST_ONLY build directory differs")
        manifest_fd = os.open(
            "build-manifest.json",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=build_fd,
        )
        manifest_raw = _read_fd(
            manifest_fd, 64 * 1024 * 1024, "published build manifest"
        )
        manifest = _strict_json_object(manifest_raw, "published build manifest")
        if _canonical_json_bytes(manifest) != manifest_raw:
            raise BuildError("published build manifest bytes are not canonical")
        if manifest.get("schema") != "plamen-native-supervisor-build-v2":
            raise BuildError("published build manifest schema differs")
        if not _BUILD_MANIFEST_V2_POST_KEY_FIELDS < set(manifest):
            raise BuildError("published build manifest closure is incomplete")
        build_preimage = {
            key: value for key, value in manifest.items()
            if key not in _BUILD_MANIFEST_V2_POST_KEY_FIELDS
        }
        if (
            manifest.get("build_key_sha256") != build_key
            or hashlib.sha256(_canonical_json_bytes(build_preimage)).hexdigest()
            != build_key
        ):
            raise BuildError("published build manifest key differs")
        output_name = manifest.get("output_basename")
        if type(output_name) is not str or _SAFE_COMPONENT.fullmatch(
            output_name
        ) is None:
            raise BuildError("published build artifact basename is invalid")
        artifact_fd = os.open(
            output_name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=build_fd,
        )
        artifact_info = os.fstat(artifact_fd)
        artifact_digest = _sha256_fd(
            artifact_fd, artifact_info.st_size
        )
        artifact = manifest.get("artifact")
        if type(artifact) is not dict or set(artifact) != {
            "path", "device", "inode", "size", "mode", "uid", "gid",
            "nlink", "mtime_ns", "ctime_ns", "sha256", "flags", "sealing",
        }:
            raise BuildError("published build artifact identity is incomplete")
        expected_path = str(root_path / build_key / output_name)
        observed_identity = _identity(artifact_info, artifact_digest)
        if (
            artifact["path"] != expected_path
            or {key: artifact[key] for key in observed_identity}
            != observed_identity
            or artifact_digest != result["artifact_sha256"]
            or result["artifact_path"] != expected_path
        ):
            raise BuildError("published build artifact differs from manifest")
        manifest_info = os.fstat(manifest_fd)
        manifest_digest = _sha256_fd(manifest_fd, manifest_info.st_size)
        expected_manifest_path = str(
            root_path / build_key / "build-manifest.json"
        )
        if (
            manifest_digest != result["manifest_sha256"]
            or result["manifest_path"] != expected_manifest_path
        ):
            raise BuildError("published build manifest result binding differs")
        symbols = manifest.get("artifact_symbol_observation")
        if symbols != {
            "schema": "plamen.native_artifact_symbols.v1",
            "expected_export": "_" + str(manifest.get("init_symbol")),
            "stdout_sha256": hashlib.sha256(
                ("_" + str(manifest.get("init_symbol")) + "\n").encode("ascii")
            ).hexdigest(),
        }:
            raise BuildError("published build exported symbol evidence differs")
        expected_packaging = {
            "module": PRODUCTION_MODULE,
            "init_symbol": f"PyInit_{PRODUCTION_MODULE}",
            "output_basename": f"{PRODUCTION_MODULE}{manifest.get('extension_suffix')}",
            "variant": "PRODUCTION",
            "test_only_build": False,
        }
        if manifest.get("production_packaging_allowlist") != expected_packaging:
            raise BuildError("published build production allowlist differs")
        if (
            manifest.get("production_packaging_allowed") is not False
            or manifest.get("required_test_only_build") is not True
            or manifest.get("variant") not in {
                "TEST_ONLY", "TEST_ONLY_PRODUCTION_SHAPE",
            }
            or result["variant"] != manifest["variant"]
            or result["module"] != manifest.get("module")
            or set(os.listdir(build_fd)) != {
                output_name, "build-manifest.json",
            }
        ):
            raise BuildError("published build TEST_ONLY type separation differs")
        return {
            "artifact_sha256": artifact_digest,
            "build_key_sha256": build_key,
            "manifest_sha256": manifest_digest,
            "schema": "plamen-native-supervisor-build-validation-v2",
            "status": "TEST_ONLY_EXACT_REPLAY",
        }
    except OSError as exc:
        raise BuildError("published TEST_ONLY build cannot be retained") from exc
    finally:
        for descriptor in (artifact_fd, manifest_fd, build_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)


TEST_ONLY_validate_published_build_v2 = validate_published_test_build_v2


def _revalidate_retained_closure(
    retained: list[tuple[int, dict[str, Any]]], label: str,
) -> None:
    for descriptor, expected in retained:
        observed = os.fstat(descriptor)
        current = _identity(observed, _sha256_fd(descriptor, observed.st_size))
        admitted = {key: expected[key] for key in current}
        if current != admitted:
            raise BuildError(f"{label} retained member changed")
        path = expected.get("path")
        if not isinstance(path, str):
            raise BuildError(f"{label} member has no canonical path")
        try:
            named_fd = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            raise BuildError(f"{label} member path is no longer retained") from exc
        try:
            if not _same_stat(observed, os.fstat(named_fd)):
                raise BuildError(f"{label} member path changed identity")
        finally:
            os.close(named_fd)


def _freeze_generated_input(
    descriptor: int, workspace_fd: int, name: str, label: str,
) -> tuple[int, dict[str, Any]]:
    """Remove every writer before returning a compiler-readable descriptor."""

    os.fsync(descriptor)
    if sys.platform == "darwin":
        os.fchmod(descriptor, 0o400)
        retained = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=workspace_fd,
        )
        if not _same_stat(os.fstat(descriptor), os.fstat(retained)):
            os.close(retained)
            raise BuildError(f"{label} descriptor identity changed before freeze")
        os.close(descriptor)
        os.unlink(name, dir_fd=workspace_fd)
        os.fsync(workspace_fd)
        descriptor = retained
        sealing = "DARWIN_UNLINKED_READONLY_RETAINED_FD_NO_WRITER"
    else:
        sealing = _make_immutable(descriptor)
    info = os.fstat(descriptor)
    digest = _sha256_fd(descriptor, info.st_size)
    return descriptor, {**_identity(info, digest), "sealing": sealing}


def _root_topology(path: Path) -> list[dict[str, Any]]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    rows: list[dict[str, Any]] = []
    current = Path("/")
    for component in absolute.parts[1:]:
        current /= component
        info = os.lstat(current)
        rows.append({
            "path": str(current), "device": int(info.st_dev),
            "inode": int(info.st_ino), "mode": int(info.st_mode),
            "uid": int(info.st_uid), "gid": int(info.st_gid),
            "symlink_target": os.readlink(current) if stat.S_ISLNK(info.st_mode) else "",
        })
    return rows


def _require_root_owned_nonwritable_ancestry(
    path: Path, label: str,
) -> list[dict[str, Any]]:
    if os.geteuid() == 0:
        raise BuildError(f"{label} cannot be admitted by a root-equivalent builder")
    root = os.lstat("/")
    if root.st_uid != 0 or root.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise BuildError(f"{label} root ancestry is writable")
    rows = _root_topology(path)
    for row in rows:
        if (
            row["uid"] != 0
            or row["mode"] & (stat.S_IWGRP | stat.S_IWOTH)
            or row["symlink_target"]
        ):
            raise BuildError(f"{label} ancestry is not root-owned and non-writable")
    return rows


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _translation_unit_closure(
    raw: bytes, state: dict[str, Any], source_snapshot_fds: tuple[int, ...],
    *, require_python_headers: bool = True,
) -> dict[str, Any]:
    marker = re.compile(rb'(?m)^# [0-9]+ "([^"\r\n]+)"(?: [0-9]+)*\r?$')
    source_aliases = {_fd_path(descriptor) for descriptor in source_snapshot_fds}
    roots: list[tuple[str, Path]] = [
        ('native_include', state["native_header_root"]),
        *(('python_include', item[0]) for item in state["include_roots"]),
        ('extension_source_include', state["extension_source_include_root"]),
        ('native_protocol_include', state["native_protocol_include_root"]),
        ('compiler_resource', state["resource_path"] / "include"),
    ]
    if state["native_darwin_include_root"] is not None:
        roots.append((
            "native_darwin_include", state["native_darwin_include_root"]
        ))
    sdk_root = state["sdk_root"]
    if sdk_root is not None:
        roots.append(("sdk", sdk_root))
    rows: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for encoded in marker.findall(raw):
        try:
            rendered = encoded.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise BuildError("preprocessed dependency marker is not UTF-8") from exc
        if rendered in {"<built-in>", "<command line>", "<stdin>"} or rendered in source_aliases:
            continue
        candidate = Path(rendered)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise BuildError("preprocessed dependency cannot be retained") from exc
        if resolved in seen:
            continue
        category = next((name for name, root in roots if _is_beneath(resolved, root)), None)
        if category is None:
            raise BuildError("preprocessor consumed a dependency outside the admitted closure")
        descriptor, opened, identity = _open_retained_regular(resolved, "preprocessed dependency")
        os.close(descriptor)
        if opened != resolved:
            raise BuildError("preprocessed dependency resolved through an unstable alias")
        seen.add(resolved)
        rows.append({"category": category, "marker_path": rendered,
                     "resolved_path": str(resolved), **identity})
    rows.sort(key=lambda item: (item["category"], item["resolved_path"]))
    if (
        not rows
        or (
            require_python_headers
            and not any(item["category"] == "python_include" for item in rows)
        )
    ):
        raise BuildError("preprocessed dependency closure is incomplete")
    topologies = [
        {"category": name, "root": str(root), "components": _root_topology(root)}
        for name, root in roots
    ]
    return {
        "kind": "DESCRIPTOR_FROZEN_PREPROCESSED_TRANSITIVE_CLOSURE_V1",
        "dependency_count": len(rows),
        "dependencies_sha256": hashlib.sha256(_canonical_json_bytes(rows)).hexdigest(),
        "dependencies": rows,
        "root_topologies_sha256": hashlib.sha256(_canonical_json_bytes(topologies)).hexdigest(),
        "root_topologies": topologies,
    }


def _freeze_artifact_writer(
    descriptor: int, workspace_fd: int, name: str,
) -> tuple[int, dict[str, Any]]:
    os.fsync(descriptor)
    os.fchmod(descriptor, 0o500)
    retained = os.open(
        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=workspace_fd,
    )
    if not _same_stat(os.fstat(descriptor), os.fstat(retained)):
        os.close(retained)
        raise BuildError("artifact identity changed while removing its writer")
    os.close(descriptor)
    info = os.fstat(retained)
    digest = _sha256_fd(retained, info.st_size)
    sealing = (
        "DARWIN_READONLY_RETAINED_FD_PENDING_ATOMIC_LINK_THEN_UF_IMMUTABLE"
        if sys.platform == "darwin" else
        "LINUX_READONLY_RETAINED_FD_POSTPUBLICATION_REHASH"
    )
    return retained, {**_identity(info, digest), "sealing": sealing}


def _inspect_artifact_symbols(
    descriptor: int, state: dict[str, Any], metadata: dict[str, Any],
) -> dict[str, Any]:
    inspector_fd = state["artifact_inspector_fd"]
    _revalidate_retained_closure(
        [(inspector_fd, metadata["artifact_symbol_inspector"])],
        "artifact symbol inspector",
    )
    completed = subprocess.run(
        (
            str(state["artifact_inspector"]), "-gjU", _fd_path(descriptor),
        ),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=state["environment"], close_fds=True,
        pass_fds=(inspector_fd, descriptor),
        executable=state["artifact_inspector_executable"],
        check=False, timeout=10,
    )
    expected = f"_{metadata['init_symbol']}\n".encode("ascii")
    if completed.returncode != 0 or completed.stdout != expected:
        raise BuildError("published artifact exports the wrong module variant")
    return {
        "schema": "plamen.native_artifact_symbols.v1",
        "expected_export": expected.decode("ascii").rstrip("\n"),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
    }


def _build_test_variant(
    output_root: Path, *, test_only: bool, test_production_shape: bool,
) -> dict[str, Any]:
    root_path, root_fd = _require_private_root(output_root)
    root_anchor = _directory_anchor(os.fstat(root_fd))
    metadata: dict[str, Any] = {}; state: dict[str, Any] = {}
    build_fd = workspace_fd = source_snapshot_fd = protocol_snapshot_fd = -1
    receipt_snapshot_fd = translation_fd = receipt_translation_fd = -1
    artifact_fd = manifest_fd = -1
    workspace_name = artifact_temp = ""
    build_key = ""
    completed_successfully = False
    try:
        metadata, state = _metadata(
            test_only, test_production_shape=test_production_shape
        )
        workspace_name = "workspace-" + secrets.token_hex(32)
        workspace_fd = _mkdir_new(root_fd, workspace_name)
        workspace_path = root_path / workspace_name
        os.fsync(root_fd)

        source_snapshot_fd, snapshot_identity = _snapshot_source(
            state["source_fd"], state["source_identity"], workspace_fd, "source.snapshot.c"
        )
        if any(snapshot_identity[key] != metadata["source_snapshot"][key] for key in ("sha256", "size", "mode", "sealing")):
            raise BuildError("source snapshot identity differs from build key")
        protocol_snapshot_fd, protocol_snapshot_identity = _snapshot_source(
            state["protocol_fd"], state["protocol_identity"], workspace_fd,
            "protocol-source.snapshot.c",
        )
        if any(
            protocol_snapshot_identity[key]
            != metadata["protocol_source_snapshot"][key]
            for key in ("sha256", "size", "mode", "sealing")
        ):
            raise BuildError("protocol source snapshot identity differs from build key")
        receipt_snapshot_identity: dict[str, Any] | None = None
        if state["receipt_fd"] >= 0:
            receipt_snapshot_fd, receipt_snapshot_identity = _snapshot_source(
                state["receipt_fd"], state["receipt_identity"], workspace_fd,
                "darwin-receipt-source.snapshot.c",
            )
            if any(
                receipt_snapshot_identity[key]
                != metadata["darwin_receipt_source_snapshot"][key]
                for key in ("sha256", "size", "mode", "sealing")
            ):
                raise BuildError(
                    "Darwin receipt source snapshot identity differs from build key"
                )
        include_flags: list[str] = []
        for native_root in (
            state["extension_source_include_root"],
            state["native_protocol_include_root"],
            state["native_header_root"],
        ):
            include_flags.extend(["-I", str(native_root)])
        if state["native_darwin_include_root"] is not None:
            include_flags.extend([
                "-I", str(state["native_darwin_include_root"])
            ])
        for number, (source_root, _commitment, rows) in enumerate(state["include_roots"]):
            del rows
            include_flags.extend(["-I", str(source_root)])

        translation_name = "translation-unit.i"
        if sys.platform == "linux":
            if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
                raise BuildError("Linux translation-unit memfd authority is unavailable")
            translation_fd = os.memfd_create(
                "plamen-native-translation-unit",
                flags=getattr(os, "MFD_CLOEXEC", 0) | os.MFD_ALLOW_SEALING,
            )
        else:
            translation_fd = os.open(
                translation_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=workspace_fd,
            )
        preprocess_flags = [
            "-std=c11", "-x", "c", "-E", *include_flags,
            "-resource-dir", str(state["resource_path"]),
            "-include", _fd_path(protocol_snapshot_fd),
        ]
        if test_only:
            preprocess_flags.append("-DPLAMEN_NATIVE_SUPERVISOR_TEST_ONLY=1")
        preprocess_command = (
            str(state["compiler"]), *state["compiler_suffix"],
            *preprocess_flags, *state["sdk_flags"],
            "-", "-o", _fd_path(translation_fd),
        )
        preprocess_template = [
            "{PINNED_COMPILER}", *state["compiler_suffix"],
            *preprocess_flags, *state["sdk_flags"],
            "{FROZEN_SOURCE_STDIN}", "-o", "{PREOWNED_TRANSLATION_UNIT_FD}",
        ]
        preprocess_template[preprocess_template.index(
            _fd_path(protocol_snapshot_fd)
        )] = "{FROZEN_PROTOCOL_SOURCE_FD}"
        compiler_executable, _authority = _executable_authority(
            state["compiler_fd"], state["compiler"]
        )
        _revalidate_retained_closure(
            state["toolchain_fds"] + state["sdk_fds"],
            "toolchain/SDK before preprocessing",
        )
        completed = subprocess.run(
            preprocess_command, cwd=workspace_path, stdin=source_snapshot_fd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=state["environment"], close_fds=True,
            pass_fds=(
                state["compiler_fd"], source_snapshot_fd,
                protocol_snapshot_fd, translation_fd,
            ),
            check=False, timeout=120, executable=compiler_executable,
        )
        if len(completed.stdout) > MAX_COMPILER_OUTPUT_BYTES:
            raise BuildError("native preprocessor output exceeded its bound")
        if completed.returncode != 0:
            diagnostic = completed.stdout.decode("utf-8", "replace")[:4096]
            raise BuildError(f"native preprocessor rejected the source: {diagnostic}")
        if dict(state["environment"]) != metadata["build_environment"]:
            raise BuildError("closed build environment changed during preprocessing")
        translation_fd, translation_identity = _freeze_generated_input(
            translation_fd, workspace_fd, translation_name, "preprocessed translation unit"
        )
        translation_raw = _read_fd(
            translation_fd, MAX_SNAPSHOT_BYTES, "preprocessed translation unit"
        )
        closure = _translation_unit_closure(
            translation_raw, state, (source_snapshot_fd, protocol_snapshot_fd)
        )
        receipt_translation_identity: dict[str, Any] | None = None
        receipt_closure: dict[str, Any] | None = None
        receipt_preprocess_template: list[str] | None = None
        receipt_preprocess_flags: list[str] | None = None
        if receipt_snapshot_fd >= 0:
            receipt_translation_name = "darwin-receipt-translation-unit.i"
            receipt_translation_fd = os.open(
                receipt_translation_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=workspace_fd,
            )
            receipt_preprocess_flags = [
                "-std=c11", "-x", "c", "-E", *include_flags,
                "-resource-dir", str(state["resource_path"]),
            ]
            receipt_preprocess_command = (
                str(state["compiler"]), *state["compiler_suffix"],
                *receipt_preprocess_flags, *state["sdk_flags"],
                "-", "-o", _fd_path(receipt_translation_fd),
            )
            receipt_preprocess_template = [
                "{PINNED_COMPILER}", *state["compiler_suffix"],
                *receipt_preprocess_flags, *state["sdk_flags"],
                "{FROZEN_DARWIN_RECEIPT_SOURCE_STDIN}", "-o",
                "{PREOWNED_DARWIN_RECEIPT_TRANSLATION_UNIT_FD}",
            ]
            _revalidate_retained_closure(
                state["toolchain_fds"] + state["sdk_fds"],
                "toolchain/SDK before Darwin receipt preprocessing",
            )
            completed = subprocess.run(
                receipt_preprocess_command, cwd=workspace_path,
                stdin=receipt_snapshot_fd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=state["environment"],
                close_fds=True,
                pass_fds=(
                    state["compiler_fd"], receipt_snapshot_fd,
                    receipt_translation_fd,
                ),
                check=False, timeout=120, executable=compiler_executable,
            )
            if len(completed.stdout) > MAX_COMPILER_OUTPUT_BYTES:
                raise BuildError(
                    "Darwin receipt preprocessor output exceeded its bound"
                )
            if completed.returncode != 0:
                diagnostic = completed.stdout.decode(
                    "utf-8", "replace"
                )[:4096]
                raise BuildError(
                    "native preprocessor rejected the Darwin receipt source: "
                    + diagnostic
                )
            receipt_translation_fd, receipt_translation_identity = (
                _freeze_generated_input(
                    receipt_translation_fd, workspace_fd,
                    receipt_translation_name,
                    "preprocessed Darwin receipt translation unit",
                )
            )
            receipt_translation_raw = _read_fd(
                receipt_translation_fd, MAX_SNAPSHOT_BYTES,
                "preprocessed Darwin receipt translation unit",
            )
            receipt_closure = _translation_unit_closure(
                receipt_translation_raw, state, (receipt_snapshot_fd,),
                require_python_headers=False,
            )
        compile_flags = [
            "-std=c11", "-x", "cpp-output", "-fPIC",
            "-fvisibility=hidden", "-Wall", "-Wextra", "-Werror",
        ]
        if sys.platform == "darwin":
            compile_flags.append("-fblocks")
        metadata["preprocess_command_template"] = preprocess_template
        metadata["preprocess_flags"] = preprocess_flags
        metadata["translation_unit"] = {
            key: translation_identity[key]
            for key in ("sha256", "size", "mode", "sealing")
        }
        metadata["translation_unit_closure"] = closure
        metadata["darwin_receipt_preprocess_command_template"] = (
            receipt_preprocess_template
        )
        metadata["darwin_receipt_preprocess_flags"] = receipt_preprocess_flags
        metadata["darwin_receipt_translation_unit"] = (
            {
                key: receipt_translation_identity[key]
                for key in ("sha256", "size", "mode", "sealing")
            }
            if receipt_translation_identity is not None else None
        )
        metadata["darwin_receipt_translation_unit_closure"] = receipt_closure
        metadata["compile_command_template"] = [
            "{PINNED_COMPILER}", *state["compiler_suffix"], *compile_flags,
            *state["sdk_flags"], "{FROZEN_TRANSLATION_UNIT_FD}",
            *(
                ["{FROZEN_DARWIN_RECEIPT_TRANSLATION_UNIT_FD}"]
                if receipt_translation_fd >= 0 else []
            ),
            *state["link_flags"], "-o", "{PREOWNED_OUTPUT_FD}",
        ]
        metadata["final_compile_flags"] = compile_flags
        build_key = hashlib.sha256(_canonical_json_bytes(metadata)).hexdigest()
        try:
            build_fd = _mkdir_new(root_fd, build_key)
        except FileExistsError as exc:
            raise BuildError("content-addressed build directory already exists") from exc
        os.fsync(root_fd)
        build_anchor = _directory_anchor(os.fstat(build_fd))
        if _directory_anchor(os.stat(
            build_key, dir_fd=root_fd, follow_symlinks=False
        )) != build_anchor:
            raise BuildError("build directory name does not identify the retained directory")

        artifact_temp = "artifact-" + secrets.token_hex(32)
        artifact_fd = os.open(artifact_temp, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=workspace_fd)
        command = (
            str(state["compiler"]), *state["compiler_suffix"], *compile_flags,
            *state["sdk_flags"], _fd_path(translation_fd),
            *(
                (_fd_path(receipt_translation_fd),)
                if receipt_translation_fd >= 0 else ()
            ),
            *state["link_flags"],
            "-o", _fd_path(artifact_fd),
        )
        pass_fds = (
            state["compiler_fd"], translation_fd,
            *((receipt_translation_fd,) if receipt_translation_fd >= 0 else ()),
            artifact_fd,
        )
        _revalidate_retained_closure(
            state["toolchain_fds"] + state["sdk_fds"],
            "toolchain/SDK before compilation",
        )
        try:
            completed = subprocess.run(
                command, cwd=workspace_path, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=state["environment"],
                close_fds=True, pass_fds=pass_fds, check=False, timeout=120,
                executable=compiler_executable,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BuildError("native compiler invocation failed") from exc
        if len(completed.stdout) > MAX_COMPILER_OUTPUT_BYTES:
            raise BuildError("native compiler output exceeded its bound")
        if completed.returncode != 0:
            diagnostic = completed.stdout.decode("utf-8", "replace")[:4096]
            raise BuildError(f"native compiler rejected the source: {diagnostic}")

        if dict(state["environment"]) != metadata["build_environment"]:
            raise BuildError("closed build environment changed during compilation")
        source_now = os.fstat(source_snapshot_fd)
        if {**_identity(source_now, _sha256_fd(source_snapshot_fd, source_now.st_size)),
            "sealing": snapshot_identity["sealing"]} != snapshot_identity:
            raise BuildError("source snapshot changed during compilation")
        protocol_now = os.fstat(protocol_snapshot_fd)
        if {
            **_identity(
                protocol_now,
                _sha256_fd(protocol_snapshot_fd, protocol_now.st_size),
            ),
            "sealing": protocol_snapshot_identity["sealing"],
        } != protocol_snapshot_identity:
            raise BuildError("protocol source snapshot changed during compilation")
        if receipt_snapshot_fd >= 0:
            receipt_now = os.fstat(receipt_snapshot_fd)
            if {
                **_identity(
                    receipt_now,
                    _sha256_fd(receipt_snapshot_fd, receipt_now.st_size),
                ),
                "sealing": receipt_snapshot_identity["sealing"],
            } != receipt_snapshot_identity:
                raise BuildError(
                    "Darwin receipt source snapshot changed during compilation"
                )
        translation_now = os.fstat(translation_fd)
        if {**_identity(translation_now, _sha256_fd(translation_fd, translation_now.st_size)),
            "sealing": translation_identity["sealing"]} != translation_identity:
            raise BuildError("frozen translation unit changed during compilation")
        if receipt_translation_fd >= 0:
            receipt_translation_now = os.fstat(receipt_translation_fd)
            if {
                **_identity(
                    receipt_translation_now,
                    _sha256_fd(
                        receipt_translation_fd,
                        receipt_translation_now.st_size,
                    ),
                ),
                "sealing": receipt_translation_identity["sealing"],
            } != receipt_translation_identity:
                raise BuildError(
                    "frozen Darwin receipt translation unit changed during compilation"
                )
        compiler_now = os.fstat(state["compiler_fd"])
        if _identity(compiler_now, _sha256_fd(state["compiler_fd"], compiler_now.st_size)) != {key: metadata["compiler"][key] for key in metadata["compiler"] if key != "path"}:
            raise BuildError("compiler executable changed during build")
        linker_now = os.fstat(state["linker_fd"])
        if _identity(linker_now, _sha256_fd(state["linker_fd"], linker_now.st_size)) != {key: metadata["linker"][key] for key in metadata["linker"] if key != "path"}:
            raise BuildError("linker executable changed during build")
        _revalidate_retained_closure(
            state["toolchain_fds"] + state["sdk_fds"],
            "toolchain/SDK after compilation",
        )

        artifact_info = os.fstat(artifact_fd)
        if not stat.S_ISREG(artifact_info.st_mode) or artifact_info.st_nlink != 1 or artifact_info.st_uid != os.geteuid() or artifact_info.st_size < 1:
            raise BuildError("compiler output is not the pre-owned private regular file")
        artifact_fd, frozen_artifact = _freeze_artifact_writer(
            artifact_fd, workspace_fd, artifact_temp
        )
        os.link(artifact_temp, state["output_name"], src_dir_fd=workspace_fd, dst_dir_fd=build_fd, follow_symlinks=False)
        os.unlink(artifact_temp, dir_fd=workspace_fd); artifact_temp = ""
        if sys.platform == "darwin":
            immutable = getattr(stat, "UF_IMMUTABLE", 0)
            if not immutable:
                raise BuildError("Darwin artifact immutable flag is unavailable")
            os.chflags(f"/dev/fd/{artifact_fd}", immutable)
            if not os.fstat(artifact_fd).st_flags & immutable:
                raise BuildError("published artifact did not retain its immutable flag")
        os.fsync(artifact_fd); os.fsync(build_fd); os.fsync(root_fd)
        artifact_symbols = _inspect_artifact_symbols(
            artifact_fd, state, metadata
        )
        published = os.stat(state["output_name"], dir_fd=build_fd, follow_symlinks=False)
        retained = os.fstat(artifact_fd)
        artifact_digest = _sha256_fd(artifact_fd, retained.st_size)
        if (
            (published.st_dev, published.st_ino, published.st_nlink,
             stat.S_IMODE(published.st_mode), published.st_size)
            != (retained.st_dev, retained.st_ino, 1, 0o500, retained.st_size)
            or artifact_digest != frozen_artifact["sha256"]
        ):
            raise BuildError("published artifact does not match retained compiler output")
        artifact_identity = {
            "path": str(root_path / build_key / state["output_name"]),
            **_identity(retained, artifact_digest),
            "sealing": (
                "DARWIN_UF_IMMUTABLE_READONLY_RETAINED_FD"
                if sys.platform == "darwin" else frozen_artifact["sealing"]
            ),
        }
        manifest = {**metadata, "build_key_sha256": build_key,
                    "source_snapshot_observed": snapshot_identity,
                    "protocol_source_snapshot_observed": protocol_snapshot_identity,
                    "darwin_receipt_source_snapshot_observed": (
                        receipt_snapshot_identity
                    ),
                    "translation_unit_observed": translation_identity,
                    "darwin_receipt_translation_unit_observed": (
                        receipt_translation_identity
                    ),
                    "artifact": artifact_identity,
                    "artifact_symbol_observation": artifact_symbols,
                    "production_packaging_allowlist": {
                        "module": PRODUCTION_MODULE, "init_symbol": f"PyInit_{PRODUCTION_MODULE}",
                        "output_basename": f"{PRODUCTION_MODULE}{state['suffix']}",
                        "variant": "PRODUCTION", "test_only_build": False,
                    }}
        manifest_bytes = _canonical_json_bytes(manifest)
        manifest_fd, manifest_identity = _write_new_retained(
            build_fd, "build-manifest.json", manifest_bytes, 0o400
        )
        os.fsync(build_fd); os.fsync(root_fd)
        final = os.fstat(artifact_fd)
        named_final = os.stat(
            state["output_name"], dir_fd=build_fd, follow_symlinks=False
        )
        final_digest = _sha256_fd(artifact_fd, final.st_size)
        if (
            _identity(final, final_digest)
            != {key: artifact_identity[key] for key in _identity(final, final_digest)}
            or not _same_stat(final, named_final)
            or final_digest != artifact_digest
        ):
            raise BuildError("artifact changed after durable publication")
        manifest_final = os.fstat(manifest_fd)
        manifest_named = os.stat(
            "build-manifest.json", dir_fd=build_fd, follow_symlinks=False
        )
        manifest_digest = _sha256_fd(manifest_fd, manifest_final.st_size)
        if (
            not _same_stat(manifest_final, manifest_named)
            or _identity(manifest_final, manifest_digest) != manifest_identity
            or manifest_digest != hashlib.sha256(manifest_bytes).hexdigest()
        ):
            raise BuildError("manifest changed after durable publication")
        if (
            _directory_anchor(os.fstat(root_fd)) != root_anchor
            or _directory_anchor(os.fstat(build_fd)) != build_anchor
            or _directory_anchor(os.stat(
                build_key, dir_fd=root_fd, follow_symlinks=False
            )) != build_anchor
        ):
            raise BuildError("publication directory authority changed")
        _remove_workspace_at(root_fd, workspace_name, workspace_fd)
        os.close(workspace_fd); workspace_fd = -1
        final_after_cleanup = os.fstat(artifact_fd)
        named_after_cleanup = os.stat(
            state["output_name"], dir_fd=build_fd, follow_symlinks=False
        )
        manifest_after_cleanup = os.fstat(manifest_fd)
        named_manifest_after_cleanup = os.stat(
            "build-manifest.json", dir_fd=build_fd, follow_symlinks=False
        )
        if (
            not _same_stat(final_after_cleanup, named_after_cleanup)
            or _sha256_fd(artifact_fd, final_after_cleanup.st_size) != artifact_digest
            or not _same_stat(manifest_after_cleanup, named_manifest_after_cleanup)
            or _sha256_fd(manifest_fd, manifest_after_cleanup.st_size)
            != manifest_digest
        ):
            raise BuildError("final TEST-ONLY descriptor handoff validation failed")
        # This is deliberately the last filesystem observation before returning.
        # Rebind the public build-key name through the retained root descriptor:
        # validating only through ``build_fd`` would accept a late rename and an
        # attacker-controlled replacement at the pathname returned below.
        rebound_build_fd = rebound_artifact_fd = rebound_manifest_fd = -1
        try:
            rebound_build_fd = os.open(
                build_key,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            if (
                _directory_anchor(os.fstat(root_fd)) != root_anchor
                or _directory_anchor(os.fstat(rebound_build_fd)) != build_anchor
                or _directory_anchor(os.fstat(build_fd)) != build_anchor
            ):
                raise BuildError("final publication directory rebound failed")
            rebound_artifact_fd = os.open(
                state["output_name"],
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=rebound_build_fd,
            )
            rebound_manifest_fd = os.open(
                "build-manifest.json",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=rebound_build_fd,
            )
            rebound_artifact = os.fstat(rebound_artifact_fd)
            rebound_manifest = os.fstat(rebound_manifest_fd)
            if (
                not _same_stat(final_after_cleanup, rebound_artifact)
                or _sha256_fd(rebound_artifact_fd, rebound_artifact.st_size)
                != artifact_digest
                or not _same_stat(manifest_after_cleanup, rebound_manifest)
                or _sha256_fd(rebound_manifest_fd, rebound_manifest.st_size)
                != manifest_digest
            ):
                raise BuildError("final publication leaf rebound failed")
        except OSError as exc:
            raise BuildError("final publication pathname rebound failed") from exc
        finally:
            for descriptor in (
                rebound_manifest_fd, rebound_artifact_fd, rebound_build_fd,
            ):
                if descriptor >= 0:
                    os.close(descriptor)
        result = {
            "schema": "plamen-native-supervisor-build-result-v2",
            "build_key_sha256": build_key, "variant": metadata["variant"],
            "module": state["module"],
            "artifact_path": artifact_identity["path"], "artifact_sha256": artifact_digest,
            "manifest_path": str(root_path / build_key / "build-manifest.json"),
            "manifest_sha256": manifest_digest,
            "path_authority": "TEST_ONLY_FINAL_DESCRIPTOR_RELATIVE_OBSERVATION",
        }
        validate_published_test_build_v2(root_path, result)
        completed_successfully = True
        return result
    finally:
        for key in (
            "source_fd", "protocol_fd", "receipt_fd", "compiler_fd", "linker_fd",
            "artifact_inspector_fd",
        ):
            descriptor = state.get(key, -1)
            if isinstance(descriptor, int) and descriptor >= 0:
                os.close(descriptor)
        for descriptor, _identity_row in state.get("toolchain_fds", []):
            os.close(descriptor)
        for descriptor, _identity_row in state.get("sdk_fds", []):
            os.close(descriptor)
        if source_snapshot_fd >= 0:
            try: _clear_immutable(source_snapshot_fd)
            except OSError: pass
            os.close(source_snapshot_fd)
        if protocol_snapshot_fd >= 0:
            try: _clear_immutable(protocol_snapshot_fd)
            except OSError: pass
            os.close(protocol_snapshot_fd)
        if receipt_snapshot_fd >= 0:
            try: _clear_immutable(receipt_snapshot_fd)
            except OSError: pass
            os.close(receipt_snapshot_fd)
        if translation_fd >= 0:
            try: _clear_immutable(translation_fd)
            except OSError: pass
            os.close(translation_fd)
        if receipt_translation_fd >= 0:
            try: _clear_immutable(receipt_translation_fd)
            except OSError: pass
            os.close(receipt_translation_fd)
        if artifact_fd >= 0:
            if not completed_successfully:
                try: _clear_immutable(artifact_fd)
                except OSError: pass
            os.close(artifact_fd)
        if manifest_fd >= 0:
            os.close(manifest_fd)
        if workspace_fd >= 0:
            if artifact_temp:
                try: os.unlink(artifact_temp, dir_fd=workspace_fd)
                except OSError: pass
            try: _remove_workspace_at(root_fd, workspace_name, workspace_fd)
            except (OSError, BuildError): pass
            os.close(workspace_fd)
        if build_fd >= 0:
            os.close(build_fd)
            if not completed_successfully and build_key:
                try:
                    build_path = root_path / build_key
                    for name in (state.get("output_name", ""), "build-manifest.json"):
                        candidate = build_path / name
                        if name and candidate.is_file() and not candidate.is_symlink():
                            try: os.chflags(candidate, 0)
                            except (AttributeError, OSError): pass
                            candidate.unlink()
                    build_path.rmdir(); os.fsync(root_fd)
                except OSError:
                    pass
        os.close(root_fd)


def _production_source_observation() -> tuple[
    list[dict[str, Any]], dict[str, bytes], list[str], dict[str, Any]
]:
    """Observe the fixed production roster without claiming build authority."""

    rows, content, blockers = _observe_production_source_roster()
    freeze: dict[str, Any] = {
        "path": str(PRODUCTION_SOURCE_FREEZE_MANIFEST),
        "schema": PRODUCTION_SOURCE_FREEZE_SCHEMA,
        "status": "MISSING",
    }
    expected_by_role: dict[str, dict[str, Any]] = {}
    decoded_freeze: dict[str, Any] | None = None
    descriptor = -1
    try:
        descriptor, resolved, identity = _open_retained_regular(
            PRODUCTION_SOURCE_FREEZE_MANIFEST,
            "production source freeze manifest",
        )
        if resolved != PRODUCTION_SOURCE_FREEZE_MANIFEST:
            raise BuildError("production source freeze manifest is aliased")
        raw = _read_fd(
            descriptor, PRODUCTION_SOURCE_FREEZE_MAX_BYTES,
            "production source freeze manifest",
        )
        decoded = decode_production_source_freeze_manifest(raw)
        decoded_freeze = decoded
        expected_by_role = {row["role"]: row for row in decoded["sources"]}
        freeze = {
            **freeze,
            "manifest_sha256": identity["sha256"],
            "roster_definition_sha256": decoded[
                "roster_definition_sha256"
            ],
            "source_count": decoded["source_count"],
            "source_roster_sha256": decoded["source_roster_sha256"],
            "status": "OBSERVED_DIAGNOSTIC_ONLY",
        }
    except (BuildError, OSError) as exc:
        try:
            os.lstat(PRODUCTION_SOURCE_FREEZE_MANIFEST)
            freeze_entry_present = True
        except FileNotFoundError:
            freeze_entry_present = False
        except OSError:
            freeze_entry_present = True
        if freeze_entry_present:
            freeze = {
                **freeze, "diagnostic": str(exc)[:1024], "status": "INVALID",
            }
            blockers.append("SOURCE_FREEZE_MANIFEST_INVALID")
        else:
            blockers.append("SOURCE_FREEZE_MANIFEST_UNAVAILABLE")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    for row in rows:
        if row["status"] != "OBSERVED_DIAGNOSTIC_ONLY":
            continue
        expected = expected_by_role.get(row["role"])
        row["expected_sha256"] = (
            expected["sha256"] if expected is not None else None
        )
        row["expected_size"] = expected["size"] if expected is not None else None
        if expected is None:
            blockers.append(
                f"SOURCE_HASH_NOT_FROZEN:{row['role']}:{row['path']}"
            )
        elif (
            row["sha256"] != expected["sha256"]
            or row["size"] != expected["size"]
        ):
            blockers.append(f"SOURCE_HASH_MISMATCH:{row['role']}:{row['path']}")
    source_blocked = any(
        code.startswith(("SOURCE_MISSING:", "SOURCE_ALIASED:",
                         "SOURCE_INVALID:", "SOURCE_HASH_"))
        or code in {
            "SOURCE_FREEZE_MANIFEST_INVALID",
            "SOURCE_FREEZE_MANIFEST_UNAVAILABLE",
        }
        for code in blockers
    )
    if decoded_freeze is not None and not source_blocked:
        try:
            _validate_frozen_runtime_source_projection(decoded_freeze)
        except (BuildError, OSError, ValueError) as exc:
            freeze["runtime_source_projection_diagnostic"] = str(exc)[:1024]
            blockers.append("RUNTIME_SOURCE_PROJECTION_INVALID")
    return rows, content, blockers, freeze


def _linux_source_observation(
    linux_policy: ModuleType, platform_authority: Any,
) -> tuple[list[dict[str, Any]], dict[str, bytes], list[str], dict[str, Any]]:
    """Observe the exact Linux roster and its architecture-qualified freeze."""

    roster = getattr(linux_policy, "LINUX_SOURCE_ROSTER", None)
    if type(roster) is not tuple or not roster:
        raise BuildError("LINUX_SOURCE_ROSTER_UNAVAILABLE")
    rows: list[dict[str, Any]] = []
    content: dict[str, bytes] = {}
    blockers: list[str] = []
    with ExitStack() as resources:
        for expected in roster:
            if (
                type(expected) is not tuple or len(expected) != 2
                or not all(type(item) is str and item for item in expected)
            ):
                raise BuildError("LINUX_SOURCE_ROSTER_MALFORMED")
            role, relative = expected
            try:
                descriptor, resolved, identity = _open_retained_regular(
                    REPOSITORY_ROOT / relative, f"Linux production {role}",
                )
            except (BuildError, OSError):
                rows.append({"path": relative, "role": role, "status": "MISSING"})
                blockers.append(f"SOURCE_MISSING:{role}:{relative}")
                continue
            resources.callback(os.close, descriptor)
            if resolved != REPOSITORY_ROOT / relative:
                rows.append({"path": relative, "role": role, "status": "ALIASED"})
                blockers.append(f"SOURCE_ALIASED:{role}:{relative}")
                continue
            if not 1 <= identity["size"] <= PRODUCTION_SOURCE_MEMBER_MAX_BYTES:
                rows.append({"path": relative, "role": role, "status": "INVALID"})
                blockers.append(f"SOURCE_INVALID:{role}:{relative}")
                continue
            raw = _read_fd(
                descriptor, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                f"Linux production {role}",
            )
            content[role] = raw
            rows.append({
                "path": relative, "role": role,
                "sha256": identity["sha256"], "size": identity["size"],
                "status": "OBSERVED_DIAGNOSTIC_ONLY",
            })

    freeze_path = REPOSITORY_ROOT / platform_authority.source_freeze_relative
    freeze: dict[str, Any] = {
        "path": str(freeze_path),
        "schema": getattr(linux_policy, "SOURCE_FREEZE_SCHEMA", ""),
        "status": "MISSING",
    }
    expected_by_role: dict[str, dict[str, Any]] = {}
    descriptor = -1
    try:
        descriptor, resolved, identity = _open_retained_regular(
            freeze_path, "Linux production source freeze manifest",
        )
        if resolved != freeze_path:
            raise BuildError("Linux production source freeze manifest is aliased")
        raw = _read_fd(
            descriptor, PRODUCTION_SOURCE_FREEZE_MAX_BYTES,
            "Linux production source freeze manifest",
        )
        decoded = linux_policy.decode_source_freeze(
            raw, authority=platform_authority,
        )
        expected_by_role = {row["role"]: row for row in decoded["sources"]}
        freeze = {
            **freeze,
            "manifest_sha256": identity["sha256"],
            "roster_definition_sha256": decoded["roster_definition_sha256"],
            "source_count": decoded["source_count"],
            "source_roster_sha256": decoded["source_roster_sha256"],
            "status": "OBSERVED_DIAGNOSTIC_ONLY",
        }
    except (BuildError, OSError, RuntimeError) as exc:
        if freeze_path.exists() or freeze_path.is_symlink():
            freeze = {**freeze, "diagnostic": str(exc)[:1024], "status": "INVALID"}
            blockers.append("LINUX_SOURCE_FREEZE_MANIFEST_INVALID")
        else:
            blockers.append("LINUX_SOURCE_FREEZE_MANIFEST_UNAVAILABLE")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    for row in rows:
        if row["status"] != "OBSERVED_DIAGNOSTIC_ONLY":
            continue
        expected = expected_by_role.get(row["role"])
        row["expected_sha256"] = expected.get("sha256") if expected else None
        row["expected_size"] = expected.get("size") if expected else None
        if expected is None:
            blockers.append(f"SOURCE_HASH_NOT_FROZEN:{row['role']}:{row['path']}")
        elif row["sha256"] != expected["sha256"] or row["size"] != expected["size"]:
            blockers.append(f"SOURCE_HASH_MISMATCH:{row['role']}:{row['path']}")
    return rows, content, sorted(set(blockers)), freeze


def render_linux_source_freeze_candidate(platform_key: str) -> bytes:
    """Render, but never publish, an exact Linux source-freeze candidate."""

    linux_policy = _load_linux_install_authority_module()
    if platform_key == "linux-x86_64":
        authority = linux_policy.platform_authority(
            platform_name="linux", machine="x86_64",
        )
    elif platform_key == "linux-arm64":
        authority = linux_policy.platform_authority(
            platform_name="linux", machine="aarch64",
        )
    else:
        raise BuildError("LINUX_SOURCE_FREEZE_TARGET_UNSUPPORTED")
    rows, _content, blockers, _freeze = _linux_source_observation(
        linux_policy, authority,
    )
    source_failures = [
        blocker for blocker in blockers
        if blocker.startswith(("SOURCE_MISSING:", "SOURCE_ALIASED:", "SOURCE_INVALID:"))
    ]
    if source_failures:
        raise BuildError(
            "Linux source freeze candidate is incomplete: "
            + ",".join(source_failures)
        )
    frozen_rows = [
        {
            "path": row["path"], "role": row["role"],
            "sha256": row["sha256"], "size": row["size"],
        }
        for row in rows
    ]
    result = {
        "platform": authority.platform_key,
        "roster_definition_sha256": (
            linux_policy.source_roster_definition_sha256()
        ),
        "schema": linux_policy.SOURCE_FREEZE_SCHEMA,
        "source_count": len(frozen_rows),
        "source_roster_sha256": linux_policy.source_content_sha256(frozen_rows),
        "sources": frozen_rows,
        "version": 2,
    }
    return _canonical_json_bytes(result)


def _linux_production_readiness() -> dict[str, Any]:
    """Return Linux-specific diagnostics without traversing Darwin policy."""

    linux_policy = _load_linux_install_authority_module()
    try:
        authority = linux_policy.platform_authority(
            platform_name=sys.platform, machine=os.uname().machine,
        )
        contract = linux_policy.production_contract(
            REPOSITORY_ROOT, platform_name=sys.platform,
            machine=os.uname().machine,
        )
    except RuntimeError as exc:
        raise BuildError(str(exc)) from None
    rows, _content, source_blockers, freeze = _linux_source_observation(
        linux_policy, authority,
    )
    blockers = list(source_blockers)
    blockers.extend(contract["transaction_admission_blockers"])
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (
        PRODUCTION_CPYTHON_ABI
    ):
        blockers.append("CPYTHON_ABI_NOT_EXACT_3_12")
    blockers = sorted(set(blockers))
    report: dict[str, Any] = {
        "schema": "plamen.native-supervisor.production-readiness.v2",
        "authority": "DIAGNOSTIC_ONLY_LOADED_PYTHON_NO_BUILD_AUTHORITY",
        "production_build_allowed": not blockers,
        "observed_python_version": [
            sys.version_info.major, sys.version_info.minor,
            sys.version_info.micro,
        ],
        "platform": sys.platform,
        "machine": os.uname().machine,
        "closure": {"linux_contract": contract},
        "source_roster": rows,
        "source_freeze_manifest": freeze,
        "blockers": blockers,
        "transaction_admission_blockers": blockers,
    }
    report["observation_sha256"] = hashlib.sha256(
        _canonical_json_bytes(report)
    ).hexdigest()
    return report


def _close_build_state(state: dict[str, Any]) -> None:
    descriptors: list[int] = []
    for key in (
        "source_fd", "protocol_fd", "compiler_fd", "linker_fd",
        "artifact_inspector_fd",
    ):
        value = state.get(key)
        if isinstance(value, int) and value >= 0:
            descriptors.append(value)
    for key in ("toolchain_fds", "sdk_fds"):
        for value, _identity_row in state.get(key, []):
            if isinstance(value, int) and value >= 0:
                descriptors.append(value)
    for descriptor in dict.fromkeys(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _diagnostic_release_file(path: Path, maximum: int) -> dict[str, Any]:
    """Describe one fixed release file without treating it as authority."""

    descriptor = -1
    try:
        descriptor, resolved, identity = _open_retained_regular(
            path, "native release evidence"
        )
        if resolved != path or identity["size"] > maximum:
            raise BuildError("native release evidence path or size differs")
        return {
            "path": str(path), "sha256": identity["sha256"],
            "size": identity["size"], "status": "PRESENT_DIAGNOSTIC_ONLY",
        }
    except (BuildError, OSError) as exc:
        return {
            "path": str(path), "status": "ABSENT_OR_INVALID",
            "diagnostic": str(exc)[:512],
        }
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canonical_absolute_path(path: Path, label: str) -> Path:
    raw = os.fspath(path)
    if (
        type(raw) is not str or not raw or "\x00" in raw
        or not raw.startswith("/") or raw.startswith("//")
        or os.path.normpath(raw) != raw
    ):
        raise BuildError(f"{label} is not canonical absolute")
    return Path(raw)


def _open_absolute_regular_nofollow(
    path: Path, maximum: int, label: str, *, allow_empty: bool = False,
) -> tuple[int, bytes, os.stat_result]:
    """Retain an exact regular leaf through a no-follow ancestor chain."""

    canonical = _canonical_absolute_path(path, label)
    parent_fd = descriptor = -1
    try:
        parent_fd = _open_directory_nofollow(canonical.parent)
        descriptor = os.open(
            canonical.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        before = os.fstat(descriptor)
        named = os.stat(
            canonical.name, dir_fd=parent_fd, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size < (0 if allow_empty else 1)
            or before.st_size > maximum
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or not _same_stat(before, named)
        ):
            raise BuildError(f"{label} retained identity differs")
        raw = (
            b"" if before.st_size == 0
            else _read_fd(descriptor, maximum, label)
        )
        after = os.fstat(descriptor)
        named_after = os.stat(
            canonical.name, dir_fd=parent_fd, follow_symlinks=False,
        )
        if not _same_stat(before, after) or not _same_stat(before, named_after):
            raise BuildError(f"{label} changed during retained replay")
        os.close(parent_fd)
        parent_fd = -1
        return descriptor, raw, after
    except (BuildError, OSError):
        if descriptor >= 0:
            os.close(descriptor)
        raise
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _exact_receipt_relative(value: Any, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise BuildError(f"{label} is malformed")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise BuildError(f"{label} is malformed") from exc
    candidate = PurePosixPath(value)
    if (
        len(raw) > 4096 or candidate.is_absolute()
        or value != candidate.as_posix()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise BuildError(f"{label} is not canonical relative")
    return value


def _receipt_authority_matches(
    authority: Any, observed: os.stat_result, digest: str, name: str,
) -> bool:
    attributes = 0
    if not int(observed.st_mode) & (
        stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    ):
        attributes |= 0x1
    expected = {
        "kind": "file", "device": int(observed.st_dev),
        "inode": int(observed.st_ino), "mode": int(observed.st_mode),
        "links": int(observed.st_nlink), "size": int(observed.st_size),
        "attributes": attributes, "reparse_tag": 0, "name": name,
        "sha256": digest, "streams": [],
    }
    return (
        type(authority) is dict
        and set(authority) == CODEX_COMMITTED_FILE_AUTHORITY_FIELDS
        and authority == expected
    )


def _read_canonical_json_file(
    path: Path, maximum: int, label: str,
) -> tuple[dict[str, Any], bytes, os.stat_result]:
    descriptor = -1
    try:
        descriptor, raw, observed = _open_absolute_regular_nofollow(
            path, maximum, label,
        )
        value = _strict_json_object(raw, label)
        if raw != _canonical_json_bytes(value):
            raise BuildError(f"{label} bytes are not canonical")
        return value, raw, observed
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_codex_terminal_evidence_v1(
    receipt: dict[str, Any], receipt_raw: bytes, codex_root: Path,
) -> dict[str, Any]:
    pointer = receipt.get("terminal_evidence")
    pointer_fields = {
        "schema", "writer_generation", "folder", "folder_authority",
        "payload_count", "file_count", "manifest_sha256",
        "folder_seal_sha256", "reserved_terminal_authority",
    }
    transaction_id = receipt["transaction_id"]
    terminal_root = (
        codex_root / ".plamen-install-transactions" / transaction_id
        / "terminal-evidence"
    )
    if (
        type(pointer) is not dict or set(pointer) != pointer_fields
        or pointer.get("schema") != "plamen.install.terminal.pointer.v1"
        or type(pointer.get("writer_generation")) is not str
        or not pointer["writer_generation"]
        or pointer.get("folder") != os.fspath(terminal_root)
        or pointer.get("payload_count") != 8
        or pointer.get("file_count") != len(CODEX_TERMINAL_EVIDENCE_FILENAMES)
        or re.fullmatch(r"[0-9a-f]{64}", pointer.get("manifest_sha256", ""))
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", pointer.get("folder_seal_sha256", "")
        ) is None
    ):
        raise BuildError("Codex terminal evidence pointer is malformed")
    directory_fd = _open_directory_nofollow(terminal_root)
    try:
        observed_names = sorted(os.listdir(directory_fd))
        if observed_names != sorted(CODEX_TERMINAL_EVIDENCE_FILENAMES):
            raise BuildError("Codex terminal evidence file roster differs")
    finally:
        os.close(directory_fd)
    values: dict[str, dict[str, Any]] = {}
    raws: dict[str, bytes] = {}
    stats: dict[str, os.stat_result] = {}
    for name in CODEX_TERMINAL_EVIDENCE_FILENAMES:
        value, raw, observed = _read_canonical_json_file(
            terminal_root / name, 32 * 1024 * 1024,
            f"Codex terminal evidence {name}",
        )
        values[name] = value
        raws[name] = raw
        stats[name] = observed
    payload_fields = {
        "precommit.json": {
            "schema", "transaction_id", "writer_generation", "source_count",
            "source_manifest_sha256", "inverse_sha256",
            "prior_receipt_authority",
        },
        "transaction.json": {
            "schema", "transaction_id", "state", "row_count",
            "rows_fold_sha256", "journal_fold_sha256",
        },
        "smoke.json": {
            "schema", "provider_invocations", "result_count", "results",
        },
        "recovery.json": {
            "schema", "outcome", "keeper_state", "recovery_command",
        },
        "broker.json": {"schema", "event_count", "event_fold_sha256"},
        "process.json": {
            "schema", "installer_pid", "keeper_pid", "smoke_pids",
            "provider_processes",
        },
        "environment.json": {
            "schema", "sanitized_environment_sha256", "interpreter_sha256",
            "script_sha256",
        },
    }
    for name, fields in payload_fields.items():
        value = values[name]
        if (
            set(value) != fields
            or value.get("schema") != (
                "plamen.install.terminal."
                + name[:-5].replace("-", "_") + ".v1"
            )
        ):
            raise BuildError("Codex terminal evidence payload schema differs")
    precommit = values["precommit.json"]
    transaction = values["transaction.json"]
    smoke = values["smoke.json"]
    process = values["process.json"]
    rows_fold = hashlib.sha256(_canonical_json_bytes([
        [row["destination_root"], row["destination_path"], row["size"],
         row["sha256"]]
        for row in receipt["rows"]
    ])).hexdigest()
    if (
        precommit.get("transaction_id") != transaction_id
        or precommit.get("writer_generation") != pointer["writer_generation"]
        or precommit.get("source_count") != receipt["source_count"]
        or precommit.get("source_manifest_sha256")
        != receipt["source_manifest_sha256"]
        or precommit.get("inverse_sha256") != receipt["inverse_sha256"]
        or transaction.get("transaction_id") != transaction_id
        or transaction.get("state") != "COMMITTED"
        or transaction.get("row_count") != receipt["source_count"]
        or transaction.get("rows_fold_sha256") != rows_fold
        or transaction.get("journal_fold_sha256") != hashlib.sha256(
            _canonical_json_bytes(receipt["journal"])
        ).hexdigest()
        or smoke.get("provider_invocations") != 0
        or type(smoke.get("results")) is not list
        or smoke.get("result_count") != len(smoke["results"])
        or process.get("provider_processes") != 0
    ):
        raise BuildError("Codex terminal evidence transaction binding differs")
    sentinel = values["sentinel.json"]
    if (
        sentinel.get("schema") != "plamen.install.terminal.sentinel.v1"
        or type(sentinel.get("terminal_prefix")) is not dict
        or type(sentinel.get("pending_suffix")) is not list
        or sentinel.get("terminal_fold_sha256") != hashlib.sha256(
            _canonical_json_bytes([
                sentinel["terminal_prefix"], sentinel["pending_suffix"],
            ])
        ).hexdigest()
    ):
        raise BuildError("Codex terminal evidence fold differs")
    manifest = values["manifest.json"]
    payload_names = CODEX_TERMINAL_EVIDENCE_FILENAMES[:8]
    if (
        set(manifest) != {
            "schema", "transaction_id", "payload_count", "payloads",
        }
        or manifest.get("schema") != "plamen.install.terminal.manifest.v1"
        or manifest.get("transaction_id") != transaction_id
        or manifest.get("payload_count") != len(payload_names)
        or type(manifest.get("payloads")) is not list
        or len(manifest["payloads"]) != len(payload_names)
    ):
        raise BuildError("Codex terminal evidence manifest is malformed")
    for ordinal, (name, row) in enumerate(
        zip(payload_names, manifest["payloads"], strict=True)
    ):
        digest = hashlib.sha256(raws[name]).hexdigest()
        if (
            type(row) is not dict
            or set(row) != {
                "ordinal", "name", "size", "sha256", "terminal_authority",
            }
            or row.get("ordinal") != ordinal or row.get("name") != name
            or row.get("size") != len(raws[name])
            or row.get("sha256") != digest
            or not _receipt_authority_matches(
                row.get("terminal_authority"), stats[name], digest, name,
            )
        ):
            raise BuildError("Codex terminal evidence payload row differs")
    manifest_digest = hashlib.sha256(raws["manifest.json"]).hexdigest()
    seal_digest = hashlib.sha256(raws["folder-seal.json"]).hexdigest()
    seal = values["folder-seal.json"]
    if (
        manifest_digest != pointer["manifest_sha256"]
        or seal_digest != pointer["folder_seal_sha256"]
        or seal.get("schema") != "plamen.install.terminal.folder_seal.v1"
        or seal.get("transaction_id") != transaction_id
        or seal.get("file_count") != len(CODEX_TERMINAL_EVIDENCE_FILENAMES)
        or seal.get("filenames") != list(CODEX_TERMINAL_EVIDENCE_FILENAMES)
        or seal.get("manifest_sha256") != manifest_digest
        or seal.get("extras") != 0
    ):
        raise BuildError("Codex terminal evidence folder seal differs")
    terminal = values["terminal-last.json"]
    terminal_fields = {
        "schema", "outcome", "transaction_id", "writer_generation",
        "receipt_sha256", "manifest_sha256", "folder_seal_sha256",
        "postclose_required", "keeper_disposition",
        "terminal_fold_sha256", "actual_suffix",
    }
    receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
    if (
        set(terminal) != terminal_fields
        or terminal.get("schema") != "plamen.install.terminal.last.v1"
        or terminal.get("outcome") != "COMMITTED"
        or terminal.get("transaction_id") != transaction_id
        or terminal.get("writer_generation") != pointer["writer_generation"]
        or terminal.get("receipt_sha256") != receipt_digest
        or terminal.get("manifest_sha256") != manifest_digest
        or terminal.get("folder_seal_sha256") != seal_digest
        or terminal.get("postclose_required") is not True
        or terminal.get("keeper_disposition") != "RELEASE_UNUSED"
        or terminal.get("terminal_fold_sha256")
        != sentinel.get("terminal_fold_sha256")
        or terminal.get("actual_suffix")
        != sentinel.get("pending_suffix")
    ):
        raise BuildError("Codex terminal-last receipt binding differs")
    return {
        "folder": os.fspath(terminal_root),
        "manifest_sha256": manifest_digest,
        "folder_seal_sha256": seal_digest,
        "terminal_last_sha256": hashlib.sha256(
            raws["terminal-last.json"]
        ).hexdigest(),
    }


def validate_codex_committed_package_v2(
    account_home: Path | None = None,
) -> dict[str, Any]:
    """Replay the committed package without importing mutable installer code.

    This Python result is diagnostic only.  It proves that readiness examined
    exact retained bytes and terminal evidence; only the native installer may
    consume those facts as publication authority.
    """

    home = _canonical_absolute_path(
        account_home or Path(pwd.getpwuid(os.getuid()).pw_dir),
        "Codex committed package account home",
    )
    codex_root = home / ".codex"
    receipt_path = codex_root / ".plamen-codex-install.json"
    receipt, raw, _receipt_stat = _read_canonical_json_file(
        receipt_path, CODEX_COMMITTED_RECEIPT_MAX_BYTES,
        "Codex committed package receipt",
    )
    if (
        set(receipt) != CODEX_COMMITTED_RECEIPT_FIELDS
        or receipt.get("schema") != CODEX_COMMITTED_RECEIPT_SCHEMA
        or receipt.get("state") != "COMMITTED"
        or re.fullmatch(r"[0-9a-f]{32}", receipt.get("transaction_id", ""))
        is None
        or receipt.get("codex_root") != os.fspath(codex_root)
        or receipt.get("plamen_root") != os.fspath(home / ".plamen")
    ):
        raise BuildError("Codex committed package receipt envelope differs")
    transaction_root = (
        codex_root / ".plamen-install-transactions"
        / receipt["transaction_id"]
    )
    owner = receipt.get("owner")
    if (
        _canonical_absolute_path(
            Path(receipt.get("source_root", "")),
            "Codex committed source root",
        ) != Path(receipt["source_root"])
        or receipt.get("transaction_root") != os.fspath(transaction_root)
        or receipt.get("stage_root") != os.fspath(transaction_root / "stage")
        or receipt.get("backup_root") != os.fspath(transaction_root / "backup")
        or receipt.get("inverse_path") != os.fspath(transaction_root / "inverse.json")
        or receipt.get("journal_path") != os.fspath(transaction_root / "journal.json")
        or any(
            re.fullmatch(r"[0-9a-f]{64}", receipt.get(name, "")) is None
            for name in (
                "source_manifest_sha256", "runtime_manifest_sha256",
                "adapter_manifest_sha256", "inverse_sha256",
            )
        )
        or type(receipt.get("last_transition_ns")) is not int
        or receipt["last_transition_ns"] <= 0
        or type(owner) is not dict
        or set(owner) != {
            "pid", "executable", "executable_sha256", "principal",
            "started_ns",
        }
        or type(owner.get("pid")) is not int or owner["pid"] <= 0
        or type(owner.get("started_ns")) is not int or owner["started_ns"] <= 0
        or type(owner.get("executable")) is not str or not owner["executable"]
        or re.fullmatch(r"[0-9a-f]{64}", owner.get("executable_sha256", ""))
        is None
        or type(owner.get("principal")) is not str
    ):
        raise BuildError("Codex committed package transaction envelope differs")
    counts = tuple(
        receipt.get(name) for name in (
            "source_count", "runtime_count", "adapter_count",
        )
    )
    rows = receipt.get("rows")
    journal = receipt.get("journal")
    if (
        any(type(value) is not int or value < 0 for value in counts)
        or counts[0] <= 0 or counts[1] + counts[2] != counts[0]
        or type(rows) is not list or type(journal) is not list
        or len(rows) != counts[0] or len(journal) != counts[0]
    ):
        raise BuildError("Codex committed package denominator differs")
    roots = {"plamen": home / ".plamen", "codex": codex_root}
    manifests: dict[str, list[tuple[str, bytes]]] = {
        "plamen": [], "codex": [],
    }
    keys: set[str] = set()
    for index, (row, entry) in enumerate(zip(rows, journal, strict=True)):
        if type(row) is not dict or set(row) != CODEX_COMMITTED_ROW_FIELDS:
            raise BuildError("Codex committed package row is malformed")
        root_name = row.get("destination_root")
        relative = _exact_receipt_relative(
            row.get("destination_path"), "Codex package destination path",
        )
        source_path = _exact_receipt_relative(
            row.get("source_path"), "Codex package source path",
        )
        size = row.get("size")
        digest = row.get("sha256")
        if (
            root_name not in roots or type(size) is not int or size < 0
            or re.fullmatch(r"[0-9a-f]{64}", digest or "") is None
        ):
            raise BuildError("Codex committed package row fields differ")
        destination = roots[root_name].joinpath(*relative.split("/"))
        key = f"{root_name}/{relative}".casefold()
        if (
            row.get("destination") != os.fspath(destination)
            or row.get("destination_key") != key or key in keys
        ):
            raise BuildError("Codex committed package destination differs")
        keys.add(key)
        descriptor = -1
        try:
            descriptor, _content, observed = _open_absolute_regular_nofollow(
                destination, max(size, 1), "Codex committed package member",
                allow_empty=True,
            )
            observed_digest = _sha256_fd(descriptor, observed.st_size)
            if (
                observed.st_size != size or observed_digest != digest
                or not _receipt_authority_matches(
                    row.get("terminal_authority"), observed,
                    observed_digest, destination.name,
                )
            ):
                raise BuildError("Codex committed package member differs")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if (
            type(entry) is not dict
            or set(entry) != CODEX_COMMITTED_JOURNAL_FIELDS
            or entry.get("index") != index
            or entry.get("destination") != os.fspath(destination)
            or entry.get("sha256") != digest
            or entry.get("terminal_authority") != row["terminal_authority"]
        ):
            raise BuildError("Codex committed package journal differs")
        manifests[root_name].append((
            source_path, f"{source_path}|{size}|{digest}\n".encode("utf-8"),
        ))
    def manifest_digest(named_rows: list[tuple[str, bytes]]) -> str:
        return hashlib.sha256(
            b"".join(raw_row for _name, raw_row in sorted(named_rows))
        ).hexdigest()
    runtime_digest = manifest_digest(manifests["plamen"])
    adapter_digest = manifest_digest(manifests["codex"])
    combined_digest = manifest_digest(
        manifests["plamen"] + manifests["codex"]
    )
    terminal_verification = receipt.get("terminal_verification")
    terminal_fields = (
        set(terminal_verification)
        if type(terminal_verification) is dict else set()
    )
    if (
        receipt.get("runtime_manifest_sha256") != runtime_digest
        or receipt.get("adapter_manifest_sha256") != adapter_digest
        or receipt.get("source_manifest_sha256") != combined_digest
        or type(terminal_verification) is not dict
        or frozenset(terminal_fields) not in CODEX_INSTALL_TERMINAL_FIELD_SHAPES
        or terminal_verification.get("verified_count") != counts[0]
        or terminal_verification.get("verified_manifest_sha256")
        != combined_digest
        or type(terminal_verification.get("completed_ns")) is not int
        or terminal_verification["completed_ns"] <= 0
        or any(
            re.fullmatch(
                r"[0-9a-f]{64}", terminal_verification.get(name, ""),
            ) is None
            for name in (
                "projection_public_key", "projection_lock_public_key",
                "projection_lock_authority_sha256",
            )
            if name in terminal_fields
        )
    ):
        raise BuildError("Codex committed package manifest fold differs")
    anchor_fd = -1
    try:
        anchor_fd, _anchor_raw, anchor_stat = _open_absolute_regular_nofollow(
            codex_root / ".plamen-install.admission.lock", 1024 * 1024,
            "Codex committed package lock", allow_empty=True,
        )
        if receipt.get("lock_identity") != [
            int(anchor_stat.st_dev), int(anchor_stat.st_ino),
        ]:
            raise BuildError("Codex committed package lock identity differs")
    finally:
        if anchor_fd >= 0:
            os.close(anchor_fd)
    terminal = _validate_codex_terminal_evidence_v1(
        receipt, raw, codex_root,
    )
    confirmed, confirmed_raw, _confirmed_stat = _read_canonical_json_file(
        receipt_path, CODEX_COMMITTED_RECEIPT_MAX_BYTES,
        "Codex committed package receipt confirmation",
    )
    if confirmed != receipt or confirmed_raw != raw:
        raise BuildError("Codex committed package receipt changed during replay")
    return {
        "schema": "plamen.codex-package-replay.v2",
        "status": "EXACT_PACKAGE_RECEIPT_REPLAYED_DIAGNOSTIC_ONLY",
        "transaction_id": receipt["transaction_id"],
        "source_count": counts[0], "runtime_count": counts[1],
        "adapter_count": counts[2],
        "source_manifest_sha256": combined_digest,
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "terminal_evidence": terminal,
    }


TEST_ONLY_validate_codex_committed_package_v2 = (
    validate_codex_committed_package_v2
)


def _source_install_handoff_present(source_content: dict[str, bytes]) -> bool:
    """Use syntax, not self-referential byte markers, for call reachability."""

    dispatch = source_content.get("source_install_dispatch", b"")
    builder = source_content.get("source_build_dispatch", b"")
    if b"--install-codex" not in dispatch:
        return False
    try:
        tree = ast.parse(builder.decode("utf-8", "strict"))
    except (UnicodeError, SyntaxError, ValueError):
        return False
    functions = {
        node.name: node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    install = functions.get("install_codex_from_source")
    transaction = functions.get("_execute_native_source_install_transaction")
    if install is None or transaction is None:
        return False
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_execute_native_source_install_transaction"
        for node in ast.walk(install)
    )


def _production_release_gate_evidence(
    source_content: dict[str, bytes], toolchain: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Map every pre-publication blocker to a current concrete observation.

    None of these Python observations can mint production authority.  They
    prevent stale unconditional TODOs from surviving after a native producer
    lands while retaining the blocker until the authenticated descriptor/
    receipt handoff itself is observable.
    """

    evidence: dict[str, Any] = {}
    blockers: list[str] = []

    def blocked(code: str, state: str, **facts: Any) -> None:
        blockers.append(code)
        evidence[code] = {"state": state, **facts}

    for selector, code in (
        ("codex", "DARWIN_CODEX_PROFILE_NOT_MATERIALIZED"),
        ("claude", "DARWIN_CLAUDE_PROFILE_NOT_MATERIALIZED"),
    ):
        blocked(
            code,
            "INSTALL_TRANSACTION_DYNAMIC_LATEST_RECEIPT_NOT_YET_COMMITTED",
            backend_selector=selector,
            acquisition_policy=(
                "verification_policy/native_backend_acquisition.v2.json"
            ),
            runtime_resolution_allowed=False,
        )

    coordinator = source_content.get("darwin_install_coordinator", b"")
    installer = source_content.get("native_installer", b"")
    builder = source_content.get("native_builder", b"")
    dispatch = source_content.get("source_install_dispatch", b"")
    coordinator_core = all(item in coordinator for item in (
        b"plamen_native_darwin_install_publish_v2",
        b"plamen_native_darwin_install_recover_v2",
        b'"publish-fds"', b'"recover-fd"',
    )) and all(item in installer for item in (
        b"plamen_native_installer_publish_v2",
        b"plamen_native_installer_recover_with_deployment_v2",
    )) and all(item in builder for item in (
        b"plamen_native_generation_stage_v2",
        b"plamen_runtime_package_manifest_revalidate_v2",
    ))
    python_handoff = _source_install_handoff_present(source_content)
    if not coordinator_core:
        blocked(
            "SOURCE_INSTALL_COORDINATOR_TRANSACTION_ABSENT",
            "NATIVE_COORDINATOR_CORE_INCOMPLETE",
        )
    elif not python_handoff:
        blocked(
            "SOURCE_INSTALL_COORDINATOR_TRANSACTION_ABSENT",
            "NATIVE_CORE_PRESENT_SOURCE_HANDOFF_ABSENT",
        )
    else:
        evidence["SOURCE_INSTALL_COORDINATOR_TRANSACTION_ABSENT"] = {
            "state": "SOURCE_HANDOFF_PRESENT_REQUIRES_LIVE_TRANSACTION_PROOF"
        }
        # Presence of a call seam is not transaction proof; retain the blocker
        # until the committed native install receipt below is validated.
        blockers.append("SOURCE_INSTALL_COORDINATOR_TRANSACTION_ABSENT")

    package_front = source_content.get("package_front", b"")
    package_rollback_symbol = b"_rollback_committed_codex_package_transaction"
    if package_rollback_symbol not in package_front:
        blocked(
            "PACKAGE_POSTCOMMIT_ROLLBACK_UNAVAILABLE",
            "FROZEN_PACKAGE_HAS_COMMIT_RECOVERY_BUT_NO_EXACT_POSTCOMMIT_COMPENSATION",
            required_symbol=package_rollback_symbol.decode("ascii"),
        )
    else:
        evidence["PACKAGE_POSTCOMMIT_ROLLBACK_UNAVAILABLE"] = {
            "state": "FROZEN_PACKAGE_ROLLBACK_SURFACE_PRESENT_REQUIRES_TRANSACTION_PROOF",
            "required_symbol": package_rollback_symbol.decode("ascii"),
        }
    if not all(marker in source_content.get("source_build_dispatch", b"") for marker in (
        b"def _create_production_cold_install_effects(",
        b"def _production_native_stage(",
        b"def _production_native_commit(",
    )):
        blocked(
            "PRODUCTION_COLD_INSTALL_EFFECT_PIPELINE_UNAVAILABLE",
            "RETAINED_PACKAGE_NATIVE_EFFECT_CALLBACKS_INCOMPLETE",
        )

    link_roles = {
        role for row in PRODUCTION_DARWIN_LINK_ROSTER
        for role in row["source_roles"]
    }
    roster_roles = {role for role, _relative in PRODUCTION_DARWIN_SOURCE_ROSTER}
    compile_inputs_complete = link_roles <= roster_roles
    blocked(
        "PRODUCTION_COMPILE_LINK_CLOSURE_UNOBSERVED",
        (
            "LINK_DENOMINATOR_PRESENT_NO_RETAINED_PRODUCTION_BUILD"
            if compile_inputs_complete and toolchain.get("status")
            == "OBSERVED_DIAGNOSTIC_ONLY"
            else "LINK_DENOMINATOR_OR_TOOLCHAIN_INCOMPLETE"
        ),
        link_source_role_count=len(link_roles),
    )
    blocked(
        "INTRINSIC_GENERATION_ARTIFACT_ROSTER_UNBUILT",
        "NO_RETAINED_SIGNED_INTRINSIC_GENERATION",
    )
    code_identity = source_content.get("darwin_code_identity", b"")
    blocked(
        "PRODUCTION_CODE_SIGNATURE_ROSTER_UNOBSERVED",
        (
            "STRICT_VALIDATOR_PRESENT_NO_SIGNED_ARTIFACT_ROSTER"
            if b"SecStaticCodeCheckValidity" in code_identity
            else "STRICT_CODE_IDENTITY_VALIDATOR_INCOMPLETE"
        ),
    )
    blocked(
        "RUNTIME_PACKAGE_MANIFEST_UNBUILT",
        (
            "NATIVE_RENDERER_AND_REVALIDATOR_PRESENT_NO_RETAINED_RUNTIME_PACKAGE"
            if all(item in builder for item in (
                b"plamen_runtime_package_manifest_render_v2",
                b"plamen_runtime_package_manifest_revalidate_v2",
            )) else "NATIVE_RUNTIME_MANIFEST_IMPLEMENTATION_INCOMPLETE"
        ),
    )
    blocked(
        "MULTI_ARTIFACT_RETAINED_INSTALL_HANDOFF_ABSENT",
        (
            "NATIVE_STAGE_AND_INSTALL_APIS_PRESENT_NO_LIVE_DESCRIPTOR_HANDOFF"
            if coordinator_core else "NATIVE_STAGE_OR_INSTALL_API_INCOMPLETE"
        ),
    )

    try:
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        account_home = Path("/NONEXISTENT-PLAMEN-NATIVE-HOME")
    native_root = account_home / ".local" / "share" / "plamen"
    active_receipt = _diagnostic_release_file(
        native_root / "share" / "plamen" / "native-install-receipt-v2.bin",
        DARWIN_INSTALL_RECEIPT_V2_SIZE,
    )
    deployment_receipt = _diagnostic_release_file(
        native_root / "share" / "plamen"
        / "native-deployment-receipt-v2.bin",
        64 * 1024,
    )
    blocked(
        "INSTALLED_CLOSURE_CODE_REQUIREMENT_RECEIPT_ABSENT",
        "NO_NATIVE_REVALIDATED_ACTIVE_RECEIPT",
        active_receipt=active_receipt,
        deployment_receipt=deployment_receipt,
    )
    try:
        package_receipt = validate_codex_committed_package_v2(account_home)
        evidence["CODEX_COMMITTED_PACKAGE_TRANSACTION_ABSENT"] = {
            "state": "EXACT_COMMITTED_PACKAGE_AND_TERMINAL_REPLAYED",
            "committed_receipt": package_receipt,
        }
    except (BuildError, OSError, KeyError, ValueError) as exc:
        package_receipt = {
            "path": str(
                account_home / ".codex" / ".plamen-codex-install.json"
            ),
            "status": "ABSENT_OR_INVALID",
            "diagnostic": str(exc)[:512],
        }
        package_state = "NO_NATIVE_CANONICAL_RECEIPT_TERMINAL_AND_ROW_REPLAY"
        blocked(
            "CODEX_COMMITTED_PACKAGE_TRANSACTION_ABSENT",
            package_state,
            committed_receipt=package_receipt,
        )
    extension = source_content.get("cpython_extension", b"")
    bridge_surface = all(item in extension for item in (
        b"acquire_darwin_tool_custody",
        b"prepare_darwin_tool_execution",
        b"execute_darwin_tool",
    ))
    fuzz_lifecycle_surface = all(item in extension for item in (
        b"prepare_darwin_tool_execution",
        b"project_darwin_fuzz_campaign_prepared",
        b"execute_darwin_fuzz_campaign",
        b"project_darwin_tool_execution_terminal",
    )) and all(item in source_content.get("darwin_effects", b"") for item in (
        b"specialized_fuzz_prepare",
        b"specialized_fuzz_campaign_execute",
        b"container_vm_stopped",
        b"guest_population_extinction_sha256",
    ))
    atomic_fuzz_admission_symbols = (
        b"APPLE_FUZZ_SERVICE_ABI_SCHEMA",
        b"AppleFuzzServiceSessionAuthority",
        b"AppleFuzzAdmissionContinuationLease",
        b"AppleFuzzLifecycleTerminal",
        b"acquire_apple_fuzz_service_session",
        b"admit_apple_fuzz_campaign",
        b"project_apple_fuzz_secure_receipt",
        b"execute_admitted_apple_fuzz_campaign",
        b"project_admitted_apple_fuzz_terminal",
    )
    missing_atomic_fuzz_admission = [
        symbol.decode("ascii")
        for symbol in atomic_fuzz_admission_symbols
        if symbol not in extension
    ]
    blocked(
        "EVM_SIGNED_TOOL_AUTHORITY_PRODUCER_ABSENT",
        (
            "BRIDGE_SURFACE_PRESENT_PROVIDER_HOOK_UNAVAILABLE"
            if bridge_surface and (
                b"native Darwin snapshot-bound tool provider hook is unavailable"
                in extension
            )
            else "BRIDGE_SURFACE_PRESENT_LIVE_SIGNED_RECEIPT_NOT_PROVEN"
            if bridge_surface
            else "SIGNED_TOOL_BRIDGE_SURFACE_INCOMPLETE"
        ),
    )
    blocked(
        "PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",
        (
            "SERVICE_EFFECTS_FUZZ_SURFACE_PRESENT_LIVE_RECEIPT_NOT_PROVEN"
            if fuzz_lifecycle_surface
            else "SERVICE_TO_EFFECTS_TO_PROVIDER_SURFACE_INCOMPLETE"
        ),
    )
    if missing_atomic_fuzz_admission:
        blocked(
            "APPLE_FUZZ_ATOMIC_ADMISSION_PRODUCERS_ABSENT",
            "LEGACY_PREPARE_ACCEPTS_CALLER_DIGESTS_AND_CANNOT_MINT_AUTHORITY",
            required_abi="plamen.apple-fuzz-service-admission.v1",
            missing_producers=missing_atomic_fuzz_admission,
        )
    return evidence, blockers


def production_readiness() -> dict[str, Any]:
    """Return a bounded diagnostic of the still-closed production build gate.

    This function deliberately returns observations, never capabilities.  The
    source installer may use exact CPython 3.12 as a one-time coordinator, but
    only the complete retained compile/sign/install transaction may authorize
    publication.  Audit execution remains native and receipt-bound.
    """

    platform_key = _production_host_platform_key()
    if platform_key.startswith("linux-"):
        return _linux_production_readiness()

    source_rows, source_content, blockers, source_freeze = (
        _production_source_observation()
    )
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (
        PRODUCTION_CPYTHON_ABI
    ):
        blockers.append("CPYTHON_ABI_NOT_EXACT_3_12")
    if sys.platform != "darwin":
        blockers.append("FIRST_PRODUCTION_PLATFORM_NOT_DARWIN")
    if os.uname().machine != "arm64":
        blockers.append("FIRST_PRODUCTION_MACHINE_NOT_ARM64")

    try:
        schema_artifact = validate_native_supervisor_schema_v2(
            source_content["native_supervisor_schema"]
        )
    except KeyError:
        blockers.append("NATIVE_SUPERVISOR_SCHEMA_ARTIFACT_UNDEFINED")
        schema_artifact = {"status": "MISSING"}
    except BuildError as exc:
        blockers.append("NATIVE_SUPERVISOR_SCHEMA_ARTIFACT_INVALID")
        schema_artifact = {
            "status": "INVALID", "diagnostic": str(exc)[:1024],
        }

    extension = source_content.get("cpython_extension", b"")
    if (
        b"v2_platform_take_initial_session" not in extension
        or re.search(
            rb"v2_platform_take_initial_session\s*\([^)]*\)\s*\{\s*"
            rb"\(void\)session;\s*return 0;\s*\}",
            extension,
            re.DOTALL,
        ) is not None
        or b"HARD_STOP_NO_ADMITTED_SERVICE_BOOTSTRAP_ABI" in extension
    ):
        blockers.append("EXTENSION_SERVICE_BOOTSTRAP_NOT_INTEGRATED")
    if b'#include "../include/plamen_broker_v2.h"' not in extension:
        blockers.append("EXTENSION_SHARED_ABI_HEADER_NOT_CONSUMED")
    if b"plamen_broker_v2_install_receipt.h" not in extension:
        blockers.append("EXTENSION_INSTALL_RECEIPT_CLOSURE_NOT_INTEGRATED")

    launcher = source_content.get("darwin_launcher", b"")
    if not all(item in launcher for item in (
        b"POSIX_SPAWN_START_SUSPENDED", b"admit_authority",
        b"service_readiness", b"spawn_register_and_resume",
    )):
        blockers.append("DARWIN_SUSPENDED_LAUNCHER_NOT_INTEGRATED")
    if any(item in launcher for item in (
        b"/Library/Application Support", b"__PLAMEN_GENERATION",
        b"{generation_id}",
    )):
        blockers.append("LAUNCHER_CONTAINS_FORBIDDEN_COMPILED_PATH")
    if (
        b"plamen_broker_v2_install_receipt.h" not in launcher
        or b"plamen_install_receipt_decode_exact" not in launcher
    ):
        blockers.append("LAUNCHER_RECEIPT_SELECTED_GENERATION_NOT_INTEGRATED")
    if b"PLAMEN_LAUNCHER_PROJECTION_BUILDER_PENDING" in launcher:
        blockers.append("LAUNCHER_NATIVE_PROJECTION_BUILDER_NOT_INTEGRATED")
    if not all(item in launcher for item in (
        b'argc == 2 && strcmp(argv[1], "readiness") == 0',
        b"service_readiness(&authority)",
        b"xpc_connection_set_peer_code_signing_requirement",
    )):
        blockers.append("AUTHENTICATED_LAUNCHER_READINESS_MODE_ABSENT")

    service = source_content.get("darwin_service", b"")
    if not all(item in service for item in (
        b"xpc_connection_create_mach_service", b"admit_service_authority",
        b"plamen_broker_v2_service_store_open",
    )):
        blockers.append("LAUNCHD_XPC_BROKER_SERVICE_NOT_INTEGRATED")
    service_store = source_content.get("darwin_service_store", b"")
    if (
        b"plamen_broker_v2_service_store_register" not in service
        or b"renameatx_np" not in service_store
        or b"fsync" not in service_store
    ):
        blockers.append("SERVICE_DURABLE_JOURNAL_NOT_INTEGRATED")
    lifecycle = source_content.get("darwin_apple_lifecycle", b"")
    effects = source_content.get("darwin_effects", b"")
    if not (
        all(item in service for item in (
            b"plamen_broker_v2_process_custody_daemon_run",
            b"plamen_broker_v2_process_custody_client_open",
            b"plamen_broker_v2_process_custody_client_readiness",
            b"effects_open.custody_client = service_authority.custody_client",
        ))
        and all(item in effects for item in (
            b"plamen_broker_v2_apple_lifecycle_bind_process_custody",
            b"plamen_broker_v2_effects_dispatch_specialized",
        ))
        and all(item in lifecycle for item in (
            b"plamen_broker_v2_process_custody_client_start",
            b"plamen_broker_v2_process_custody_client_wait",
            b"plamen_broker_v2_process_custody_client_revoke",
        ))
    ):
        blockers.append("SERVICE_PROCESS_CUSTODY_NOT_INTEGRATED")
    if b"dispatch_unsupported_operation" in service:
        blockers.append("SERVICE_OPERATION_DISPATCH_NOT_INTEGRATED")
    if not all(item in service for item in (
        b"plamen_broker_v2_process_custody_client_readiness",
        b"installation_receipt_sha256",
        b"generation_id_sha256",
        b"service_sha256",
    )):
        blockers.append("BROKER_CUSTODY_READINESS_CHAIN_ABSENT")

    custody_daemon = source_content.get("darwin_process_custody_daemon", b"")
    custody_client = source_content.get("darwin_process_custody_client", b"")
    launchd_installer = source_content.get("darwin_launchd_installer", b"")
    launchd_readiness = source_content.get("darwin_launchd_readiness", b"")
    if not all(item in custody_daemon for item in (
        b'OP_STATUS "status"', b"broker_session_id",
        b"installation_receipt_sha256", b"generation_id_sha256",
        b"service_sha256",
    )) or not all(item in custody_client for item in (
        b"plamen_broker_v2_process_custody_client_readiness",
        b"constant_equal(&observed, expected, sizeof(observed))",
        b"reject_connection(client)",
    )):
        blockers.append("CUSTODY_AUTHENTICATED_STATUS_PROTOCOL_ABSENT")
    if not all(item in launchd_installer for item in (
        b"plamen_native_launchd_production_effects_v2",
        b"PLAMEN_LAUNCHD_ROLE_CUSTODY_V2",
        b"PLAMEN_LAUNCHD_ROLE_BROKER_V2",
        b"plamen_native_launchd_authenticated_ready_v2",
    )) or not all(item in launchd_readiness for item in (
        b'"readiness"', b"POSIX_SPAWN_CLOEXEC_DEFAULT",
        b"plamen_install_receipt_member_revalidate",
    )):
        blockers.append("AUTHENTICATED_LAUNCHD_DEPLOYMENT_READINESS_ABSENT")

    launchd = source_content.get("launchd_manifest", b"")
    if (
        not launchd
        or b"com.plamen.audit.broker.v2" not in launchd
        or b"ProgramArguments" not in launchd
    ):
        blockers.append("LAUNCHD_MANIFEST_NOT_INTEGRATED")

    process_source = source_content.get("darwin_process", b"")
    if re.search(
        rb"plamen_broker_v2_production_available\s*\(void\)\s*"
        rb"\{\s*return 0;\s*\}",
        process_source,
        re.DOTALL,
    ) is not None:
        blockers.append("DARWIN_PROCESS_PRODUCTION_ENTRYPOINT_UNAVAILABLE")

    toolchain: dict[str, Any]
    state: dict[str, Any] = {}
    try:
        metadata, state = _metadata(False, test_production_shape=True)
        dynamic = metadata["toolchain_dynamic_closure"]
        sdk = metadata["sdk"]
        toolchain = {
            "status": "OBSERVED_DIAGNOSTIC_ONLY",
            "interpreter": metadata["interpreter"],
            "compiler": metadata["compiler"],
            "compiler_resolution": metadata["compiler_resolution"],
            "linker": metadata["linker"],
            "sdk": sdk,
            "dynamic_closure_member_count": len(dynamic.get("members", [])),
            "dynamic_closure_sha256": hashlib.sha256(
                _canonical_json_bytes(dynamic)
            ).hexdigest(),
        }
    except (BuildError, OSError, ValueError) as exc:
        blockers.append("COMPILER_SDK_TOOLCHAIN_CLOSURE_UNAVAILABLE")
        toolchain = {
            "status": "UNAVAILABLE",
            "diagnostic": str(exc)[:1024],
        }
    finally:
        _close_build_state(state)

    release_gate_evidence, release_blockers = (
        _production_release_gate_evidence(source_content, toolchain)
    )
    blockers.extend(release_blockers)
    blockers = sorted(set(blockers))
    closure = {
        "artifact_roster": [
            {
                **row,
                "artifact": row["artifact"].replace(
                    "{EXT_SUFFIX}", ".cpython-312-darwin.so"
                ),
                "compile_flags": list(row["compile_flags"]),
                "flags": list(row["flags"]),
                "source_roles": list(row["source_roles"]),
            }
            for row in PRODUCTION_DARWIN_LINK_ROSTER
        ],
        "cpython_abi": list(PRODUCTION_CPYTHON_ABI),
        "framework_roster": list(PRODUCTION_DARWIN_FRAMEWORK_ROSTER),
        "generation_install_roster": [
            item.replace("{EXT_SUFFIX}", ".cpython-312-darwin.so")
            for item in PRODUCTION_DARWIN_GENERATION_INSTALL_ROSTER
        ],
        "install_root_deployment_roster": [
            item.replace("{EXT_SUFFIX}", ".cpython-312-darwin.so")
            for item in PRODUCTION_DARWIN_INSTALL_ROOT_DEPLOYMENT_ROSTER
        ],
        "public_topology": dict(PRODUCTION_DARWIN_PUBLIC_TOPOLOGY),
        "generation_contract": {
            "schema": PRODUCTION_GENERATION_ID_SCHEMA,
            "status": "FROZEN_ID_FORMULA_LAYOUT_AND_INSTALL_AUTHORITY_PENDING",
            "directory_template": "{store_root}/generations/{generation_id}",
            "generation_id_formula": (
                "SHA256(PLAMEN-INTRINSIC-GENERATION-V2\\0 || fixed big-"
                "endian platform/arch/count header || exact receipt-order "
                "8-member role/path/mode/size/SHA256 rows)"
            ),
            "intrinsic_artifact_roles": list(
                PRODUCTION_GENERATION_INTRINSIC_ROLES
            ),
            "deployment_roles_excluded_from_generation_id": list(
                PRODUCTION_GENERATION_DEPLOYMENT_ROLES
            ),
            "intrinsic_source_observation_sha256": hashlib.sha256(
                _canonical_json_bytes(source_rows)
            ).hexdigest(),
            "compiler_sdk_observation_sha256": hashlib.sha256(
                _canonical_json_bytes(toolchain)
            ).hexdigest(),
            "compiler_sdk_in_generation_id": False,
            "python_abi_binding": {
                "implementation": "cpython",
                "version": list(PRODUCTION_CPYTHON_ABI),
                "soabi": "cpython-312-darwin",
                "extension_suffix": ".cpython-312-darwin.so",
            },
            "receipt_required_bindings": [
                "generation_id",
                "intrinsic_roster_sha256",
                "artifact_sha256_size_mode_vnode_roster",
                "python_abi",
                "launchd_plist_absolute_path_sha256_mode_vnode",
                "launchctl_bootstrap_result",
                "authenticated_service_handshake",
                "stable_internal_launcher_hardlink_same_vnode",
            ],
            "install_receipt_v2": {
                "install_root_relative_path": (
                    "share/plamen/native-install-receipt-v2.bin"
                ),
                "generation_member": False,
                "size": DARWIN_INSTALL_RECEIPT_V2_SIZE,
                "hashed_prefix_size": DARWIN_INSTALL_RECEIPT_V2_HASHED_SIZE,
                "encoding": "FIXED_BIG_ENDIAN_PLMINS2_VERSION_2",
                "member_roster": [
                    {
                        "role": role, "role_id": role_id,
                        "relative_path": relative, "mode": mode,
                        "signing_identifier": identifier,
                        "signed": signed,
                    }
                    for role, role_id, relative, mode, identifier, signed
                    in DARWIN_INSTALL_RECEIPT_V2_MEMBERS
                ],
                "self_digest_or_vnode_encoded": False,
                "precommit_checkpoint": (
                    "SHA256(PLAMEN-INSTALL-PRECOMMIT-V2\\0 || receipt[0:16352] "
                    "with bytes80:112 zero)"
                ),
                "production_serializer_authority": (
                    "PENDING_RETAINED_SOURCE_COORDINATOR_HANDOFF_TO_NATIVE_INSTALLER"
                ),
            },
            "runtime_package_manifest_v2": {
                "generation_relative_path": (
                    "share/plamen/runtime-package-manifest-v2.bin"
                ),
                "runtime_root": RUNTIME_PACKAGE_MANIFEST_V2_ROOT,
                "encoding": "STRICT_BIG_ENDIAN_PLMRPM2_VERSION_2",
                "header_size": RUNTIME_PACKAGE_MANIFEST_V2_HEADER_SIZE,
                "external_binding_size": (
                    RUNTIME_PACKAGE_MANIFEST_V2_BINDING_SIZE
                ),
                "row_size": RUNTIME_PACKAGE_MANIFEST_V2_ROW_SIZE,
                "trailer_size": RUNTIME_PACKAGE_MANIFEST_V2_TRAILER_SIZE,
                "maximum_entries": RUNTIME_PACKAGE_MANIFEST_V2_MAX_ENTRIES,
                "maximum_path_bytes": RUNTIME_PACKAGE_MANIFEST_V2_MAX_PATH_BYTES,
                "maximum_depth": RUNTIME_PACKAGE_MANIFEST_V2_MAX_DEPTH,
                "maximum_file_bytes": RUNTIME_PACKAGE_MANIFEST_V2_MAX_FILE_BYTES,
                "maximum_total_file_bytes": (
                    RUNTIME_PACKAGE_MANIFEST_V2_MAX_TOTAL_BYTES
                ),
                "required_files": list(
                    RUNTIME_PACKAGE_MANIFEST_V2_REQUIRED_FILES
                ),
                "target_arch_enumeration": dict(
                    RUNTIME_PACKAGE_MANIFEST_V2_TARGET_ARCHES
                ),
                "reference_fields": list(
                    RUNTIME_PACKAGE_MANIFEST_V2_REFERENCE_FIELDS
                ),
                "digest_fields": list(
                    RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS
                ),
                "field_order_kat_sha256": (
                    RUNTIME_PACKAGE_MANIFEST_V2_FIELD_ORDER_KAT.hex()
                ),
                "runtime_layout_request_value": "SHA256_FULL_MANIFEST_BYTES",
                "directory_mode": 0o500,
                "file_mode": 0o400,
                "link_policy": "NO_SYMLINKS_SPECIAL_FILES_OR_FILE_HARDLINKS",
                "manifest_in_runtime_census": False,
                "production_generator_authority": (
                    "PENDING_RETAINED_SOURCE_COORDINATOR_HANDOFF_TO_NATIVE_INSTALLER"
                ),
            },
            "darwin_codex_profile_v2": {
                "runtime_relative_path": DARWIN_CODEX_PROFILE_V2_PATH,
                "size": DARWIN_CODEX_PROFILE_V2_SIZE,
                "hashed_prefix_size": DARWIN_CODEX_PROFILE_V2_HASHED_SIZE,
                "encoding": "STRICT_BIG_ENDIAN_PLMBPF2_VERSION_2",
                "provider_identifier": (
                    DARWIN_CODEX_PROFILE_V2_PROVIDER_IDENTIFIER
                ),
                "provider_team": DARWIN_CODEX_PROFILE_V2_PROVIDER_TEAM,
                "backend_identifier": (
                    DARWIN_CODEX_PROFILE_V2_BACKEND_IDENTIFIER
                ),
                "backend_team": DARWIN_CODEX_PROFILE_V2_BACKEND_TEAM,
                "release_selection": (
                    "INSTALL_TRANSACTION_RESOLVES_LATEST_THEN_BINDS_EXACT_"
                    "SIGNED_GENERATION_RECEIPT"
                ),
                "acquisition_policy": (
                    "verification_policy/native_backend_acquisition.v2.json"
                ),
                "backend_selector": (
                    DARWIN_CODEX_PROFILE_V2_BACKEND_SELECTOR
                ),
                "provider_selector": (
                    DARWIN_CODEX_PROFILE_V2_PROVIDER_SELECTOR
                ),
                "source_authority": "RETAINED_SIGNED_GENERATION_AUTHORITY",
            },
            "darwin_claude_profile_v2": {
                "runtime_relative_path": DARWIN_CLAUDE_PROFILE_V2_PATH,
                "size": DARWIN_CODEX_PROFILE_V2_SIZE,
                "hashed_prefix_size": DARWIN_CODEX_PROFILE_V2_HASHED_SIZE,
                "encoding": "STRICT_BIG_ENDIAN_PLMBPF2_VERSION_2",
                "provider_identifier": (
                    DARWIN_CODEX_PROFILE_V2_PROVIDER_IDENTIFIER
                ),
                "provider_team": DARWIN_CODEX_PROFILE_V2_PROVIDER_TEAM,
                "backend_identifier": (
                    DARWIN_CLAUDE_PROFILE_V2_BACKEND_IDENTIFIER
                ),
                "backend_team": DARWIN_CLAUDE_PROFILE_V2_BACKEND_TEAM,
                "release_selection": (
                    "INSTALL_TRANSACTION_RESOLVES_LATEST_THEN_BINDS_EXACT_"
                    "SIGNED_GENERATION_RECEIPT"
                ),
                "acquisition_policy": (
                    "verification_policy/native_backend_acquisition.v2.json"
                ),
                "backend_selector": (
                    DARWIN_CLAUDE_PROFILE_V2_BACKEND_SELECTOR
                ),
                "provider_selector": (
                    DARWIN_CODEX_PROFILE_V2_PROVIDER_SELECTOR
                ),
                "credential_source": (
                    "MACOS_SECURITY_FRAMEWORK_EXACT_CLAUDE_CODE_CREDENTIALS_"
                    "CURRENT_UID_TO_PREOWNED_PRIVATE_NO_LINK_FD"
                ),
                "guest_materialization": (
                    "/run/plamen/private/claude/.credentials.json"
                ),
                "source_authority": "RETAINED_SIGNED_GENERATION_AUTHORITY",
            },
            "publication_order": [
                "retain-intrinsic-artifact-roster",
                "compute-intrinsic-generation-id",
                "publish-generation-directory",
                "render-and-retain-deployment-plist",
                "write-and-retain-install-receipt",
                "launchctl-bootstrap",
                "authenticated-service-handshake",
                "publish-stable-internal-launcher-last",
            ],
            "retained_handoff_required": True,
            "source_install_coordinator": {
                "interpreter_abi": "cpython-312-darwin",
                "argv": [
                    "{selected_python_3_12}", "-I", "-B",
                    "{descriptor_admitted_repository}/scripts/"
                    "build_posix_native_supervisor.py",
                    "--install-codex",
                ],
                "environment": {
                    "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
                    "PYTHONHASHSEED": "0",
                },
                "tools": dict(PRODUCTION_DARWIN_SOURCE_INSTALL_TOOLS),
                "home_derivation": "getpwuid_r(getuid()).pw_dir",
                "status": "TRANSACTION_NOT_YET_INTEGRATED",
            },
            "code_signature_contract": {
                "identifiers": dict(PRODUCTION_DARWIN_SIGNING_IDENTIFIERS),
                "team_identifier": "",
                "sign_command_template": [
                    "/usr/bin/codesign", "--force", "--sign", "-",
                    "--identifier", "{exact_identifier}", "--timestamp=none",
                    "{retained_staged_artifact}",
                ],
                "validation": [
                    "codesign --verify --strict",
                    "SecStaticCodeCheckValidity(kSecCSStrictValidate)",
                ],
                "ordering": (
                    "compile -> deterministic-ad-hoc-sign -> strict-validate -> "
                    "observe identifier/team/CDHash -> final SHA256 -> receipt"
                ),
                "receipt_binds": [
                    "post_sign_sha256", "identifier", "empty_team_identifier",
                    "cdhash", "mode", "vnode",
                ],
            },
            "linux_reserved_denominator": {
                "status": (
                    "NATIVE_DESCRIPTOR_EXECUTOR_AND_DURABLE_RECOVERY_"
                    "IMPLEMENTED_LIVE_ROOTLESS_LINUX_RECEIPTS_PENDING"
                ),
                "admission_source_roster": list(
                    PRODUCTION_LINUX_ADMISSION_SOURCE_ROSTER
                ),
                "admission_proves": [
                    "exact-rootless-component-package-receipts",
                    "retained-componentwise-nofollow-descriptors",
                    "private-root-and-overlay-topology",
                    "empty-delegated-cgroup-v2-leaf-with-cgroup-kill",
                    "immutable-oci-manifest-and-platform-inspect",
                    "closed-read-only-command-schema",
                    "integrity-bound-receipt-requiring-broker-authentication",
                ],
                "admission_does_not_grant": [
                    "container-lifecycle",
                    "cgroup-population-zero-after-execution",
                    "overlay-cleanup",
                    "durable-recovery",
                    "artifact-export",
                    "python-authority",
                ],
                "lifecycle_contract_proves": [
                    "durable-intent-before-effect-state-machine",
                    "operation-key-idempotence-and-conflict-rejection",
                    "restart-replay-and-tamper-evident-journal",
                    "network-none-default-and-verified-egress-handoff",
                    "closed-create-start-wait-term-kill-cleanup-remove-schema",
                    "bounded-output-and-exit-semantics-receipt-schema",
                ],
                "lifecycle_still_unverified": [
                    "live-podman-postcondition-reconciliation",
                    "overlay-mount-and-upper-work-cleanup",
                    "live-rootless-receipt-authentication",
                ],
                "intrinsic_roster": [
                    {"role": role, "relative_path": relative, "mode": mode}
                    for role, relative, mode
                    in PRODUCTION_LINUX_RESERVED_INTRINSIC_ROSTER
                ],
                "native_endpoints": dict(PRODUCTION_LINUX_NATIVE_ENDPOINTS),
                "install_receipt": {
                    **dict(PRODUCTION_LINUX_INSTALL_RECEIPT_V2),
                    "member_roles": list(
                        PRODUCTION_LINUX_INSTALL_RECEIPT_V2["member_roles"]
                    ),
                    "member_bindings": list(
                        PRODUCTION_LINUX_INSTALL_RECEIPT_V2["member_bindings"]
                    ),
                    "authority_bindings": list(
                        PRODUCTION_LINUX_INSTALL_RECEIPT_V2[
                            "authority_bindings"
                        ]
                    ),
                },
                "process_custody_functions": [
                    "plamen_broker_v2_linux_cgroup_leaf_admit",
                    "plamen_broker_v2_linux_process_spawn_retained",
                    "plamen_broker_v2_linux_process_revalidate",
                    "plamen_broker_v2_linux_process_wait_or_extinguish",
                    "plamen_broker_v2_linux_process_extinguish",
                    "plamen_broker_v2_linux_process_close",
                ],
                "lifecycle_functions": [
                    "plamen_broker_v2_podman_cgroup_path_revalidate",
                    "plamen_broker_v2_podman_lifecycle_execute_journaled",
                ],
                "guest_runtime": {
                    **dict(PRODUCTION_LINUX_GUEST_RUNTIME),
                    "interpreter_argv": list(
                        PRODUCTION_LINUX_GUEST_RUNTIME["interpreter_argv"]
                    ),
                    "forge_required_flags": list(
                        PRODUCTION_LINUX_GUEST_RUNTIME["forge_required_flags"]
                    ),
                },
            },
        },
        "source_roster": source_rows,
        "source_freeze_manifest": source_freeze,
        "native_supervisor_schema_artifact": schema_artifact,
        "release_gate_evidence": release_gate_evidence,
        "toolchain": toolchain,
    }
    transaction_admission_blockers = sorted(
        set(blockers) - PRODUCTION_COLD_INSTALL_OUTPUT_BLOCKERS
    )
    report: dict[str, Any] = {
        "schema": "plamen.native-supervisor.production-readiness.v2",
        "authority": "DIAGNOSTIC_ONLY_LOADED_PYTHON_NO_BUILD_AUTHORITY",
        "production_build_allowed": not transaction_admission_blockers,
        "observed_python_version": [
            sys.version_info.major, sys.version_info.minor,
            sys.version_info.micro,
        ],
        "platform": sys.platform,
        "machine": os.uname().machine,
        "closure": closure,
        "blockers": blockers,
        "transaction_admission_blockers": transaction_admission_blockers,
    }
    report["observation_sha256"] = hashlib.sha256(
        _canonical_json_bytes(report)
    ).hexdigest()
    return report


def build(output_root: Path, *, test_only: bool) -> dict[str, Any]:
    if type(test_only) is not bool:
        raise BuildError("test_only must be an exact bool")
    captured_test_only = test_only
    if not captured_test_only:
        readiness = production_readiness()
        raise BuildError(
            "production build hard-stop: authenticated native builder and "
            "descriptor handoff are not integrated; blockers="
            + ",".join(readiness["blockers"])
        )
    return _build_test_variant(
        output_root, test_only=True, test_production_shape=False
    )


def TEST_ONLY_build_production_shape(output_root: Path) -> dict[str, Any]:
    return _build_test_variant(
        output_root, test_only=False, test_production_shape=True
    )


def _retained_executable_argv(
    path: Path, descriptor: int, label: str,
) -> str:
    """Return the narrowest executable name supported by the current host.

    Linux can execute the inherited descriptor through ``/dev/fd``.  Darwin's
    fdesc mount rejects executable opens with ``EACCES``; like ``codesign``, it
    therefore requires the named vnode.  The Darwin caller must retain the FD
    across the child and rejoin it immediately after the process returns.
    """

    if type(descriptor) is not int or descriptor < 3:
        raise BuildError(f"{label} retained descriptor differs")
    try:
        opened = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        access_mode = (
            fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            if fcntl is not None else -1
        )
    except OSError as exc:
        raise BuildError(f"{label} retained executable is unavailable") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid not in {0, os.geteuid()}
        or (
            opened.st_nlink != 1
            if opened.st_uid == os.geteuid() else opened.st_nlink < 1
        )
        or not stat.S_IMODE(opened.st_mode) & stat.S_IXUSR
        or stat.S_IMODE(opened.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        or access_mode != os.O_RDONLY or not _same_stat(opened, named)
    ):
        raise BuildError(f"{label} retained executable authority differs")
    return str(path) if sys.platform == "darwin" else _fd_path(descriptor)


def _run_native_generation_stage_cli(
    executable: Path, *, staging_parent_fd: int, runtime_root_fd: int,
    member_fds: list[int], broker_plist_fd: int, custody_plist_fd: int,
    staged_name: str, executable_fd: int | None = None,
) -> str:
    """Hand the complete retained generation roster to the native stager."""

    if (
        type(member_fds) is not list or len(member_fds) != 10
        or _SAFE_COMPONENT.fullmatch(staged_name) is None
    ):
        raise BuildError("native generation handoff roster differs")
    executable_argv = str(executable)
    descriptors = [
        staging_parent_fd, runtime_root_fd, *member_fds,
        broker_plist_fd, custody_plist_fd,
    ]
    if executable_fd is not None:
        executable_argv = _retained_executable_argv(
            executable, executable_fd, "native generation stager",
        )
        descriptors.append(executable_fd)
    if any(type(fd) is not int or fd < 3 for fd in descriptors):
        raise BuildError("native generation handoff descriptor differs")
    try:
        completed = subprocess.run(
            [
                executable_argv, "stage-fds",
                str(staging_parent_fd), str(runtime_root_fd),
                *(str(fd) for fd in member_fds),
                str(broker_plist_fd), str(custody_plist_fd), staged_name,
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=_CLOSED_ENV, timeout=120,
            pass_fds=tuple(dict.fromkeys(descriptors)), close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("native generation retained handoff failed") from exc
    if executable_fd is not None:
        _require_path_descriptor_rejoin(
            executable, executable_fd, "native generation stager",
        )
    if (
        completed.returncode != 0 or completed.stderr
        or re.fullmatch(rb"[0-9a-f]{64}\n", completed.stdout) is None
    ):
        raise BuildError("native generation retained handoff failed")
    return completed.stdout[:-1].decode("ascii")


def _run_native_install_coordinator_cli(
    executable: Path, *, install_root_fd: int, staging_parent_fd: int,
    receipt_fd: int, install_root: Path, staged_name: str,
    generation_id: str, executable_fd: int | None = None,
) -> None:
    """Publish an already-staged generation through the native transaction."""

    if (
        re.fullmatch(r"[0-9a-f]{64}", generation_id) is None
        or _SAFE_COMPONENT.fullmatch(staged_name) is None
    ):
        raise BuildError("native install coordinator arguments differ")
    executable_argv = str(executable)
    descriptors = [install_root_fd, staging_parent_fd, receipt_fd]
    if executable_fd is not None:
        executable_argv = _retained_executable_argv(
            executable, executable_fd, "native install coordinator",
        )
        descriptors.append(executable_fd)
    if any(type(fd) is not int or fd < 3 for fd in descriptors):
        raise BuildError("native install coordinator descriptor differs")
    try:
        completed = subprocess.run(
            [
                executable_argv, "publish-fds", str(install_root_fd),
                str(staging_parent_fd), str(receipt_fd), str(install_root),
                staged_name, generation_id,
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=_CLOSED_ENV, timeout=180,
            pass_fds=tuple(descriptors), close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("native install coordinator transaction failed") from exc
    if executable_fd is not None:
        _require_path_descriptor_rejoin(
            executable, executable_fd, "native install coordinator",
        )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise BuildError("native install coordinator transaction failed")


def _run_native_prepare_publish_cli(
    executable: Path, *, install_root_fd: int, staging_parent_fd: int,
    runtime_root_fd: int, receipt_output_fd: int,
    broker_plist_output_fd: int, custody_plist_output_fd: int,
    install_root: Path, staged_name: str, generation_id: str | None,
    projection_schema_sha256: str, protocol_schema_sha256: str,
    runtime_bindings: dict[str, Any],
    member_fds: list[int], signed_identities: list[dict[str, str]],
    retain_postcommit: bool = False,
    image_member_rows_fd: int | None = None,
    image_receipt_output_fd: int | None = None,
    specialized_policy_self_sha256: str | None = None,
    specialized_policy_bytes_sha256: str | None = None,
    source_bootstrap_receipt_fd: int | None = None,
    source_bootstrap_producer_verifier_key_fd: int | None = None,
    resume_specialized: bool = False,
    executable_fd: int | None = None,
) -> None:
    """Run the single-process retained native prepare/publish transaction."""

    specialized_values = (
        image_member_rows_fd, image_receipt_output_fd,
        specialized_policy_self_sha256, specialized_policy_bytes_sha256,
    )
    specialized = all(value is not None for value in specialized_values)
    source_bootstrap_values = (
        source_bootstrap_receipt_fd,
        source_bootstrap_producer_verifier_key_fd,
    )
    source_bootstrap = all(
        value is not None for value in source_bootstrap_values
    )
    if (
        type(member_fds) is not list or len(member_fds) != 10
        or type(signed_identities) is not list
        or len(signed_identities) != 6
        or type(retain_postcommit) is not bool
        or type(resume_specialized) is not bool
        or (retain_postcommit and generation_id is not None)
        or (resume_specialized and (
            not specialized or not source_bootstrap or retain_postcommit
            or generation_id is not None
        ))
        or (any(value is not None for value in specialized_values)
            and not specialized)
        or (any(value is not None for value in source_bootstrap_values)
            and not source_bootstrap)
        or (specialized and generation_id is not None)
        or (specialized and (
            type(image_member_rows_fd) is not int
            or image_member_rows_fd < 3
            or type(image_receipt_output_fd) is not int
            or image_receipt_output_fd < 3
            or re.fullmatch(
                r"[0-9a-f]{64}", specialized_policy_self_sha256 or "",
            ) is None
            or re.fullmatch(
                r"[0-9a-f]{64}", specialized_policy_bytes_sha256 or "",
            ) is None
        ))
        or (source_bootstrap and (
            type(source_bootstrap_receipt_fd) is not int
            or source_bootstrap_receipt_fd < 3
            or type(source_bootstrap_producer_verifier_key_fd) is not int
            or source_bootstrap_producer_verifier_key_fd < 3
        ))
        or _SAFE_COMPONENT.fullmatch(staged_name) is None
        or any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in (
                (() if generation_id is None else (generation_id,)) + (
                projection_schema_sha256,
                protocol_schema_sha256,
                )
            )
        )
    ):
        raise BuildError("native prepare/publish handoff arguments differ")
    # Reuse the exact ABI encoder as a strict field/reference validator.  The
    # coordinator independently renders the authoritative manifest bytes.
    _runtime_manifest_binding(runtime_bindings)
    executable_argv = str(executable)
    descriptors = [
        install_root_fd, staging_parent_fd, runtime_root_fd,
        receipt_output_fd, broker_plist_output_fd,
        custody_plist_output_fd, *member_fds,
    ]
    if executable_fd is not None:
        executable_argv = _retained_executable_argv(
            executable, executable_fd, "native install coordinator",
        )
        descriptors.append(executable_fd)
    if specialized:
        descriptors.extend([image_member_rows_fd, image_receipt_output_fd])
    if source_bootstrap:
        descriptors.extend([
            source_bootstrap_receipt_fd,
            source_bootstrap_producer_verifier_key_fd,
        ])
    if any(type(fd) is not int or fd < 3 for fd in descriptors):
        raise BuildError("native prepare/publish descriptor roster differs")
    normalized: list[dict[str, str]] = []
    for index, identity in enumerate(signed_identities):
        if (
            type(identity) is not dict
            or set(identity) != {"identifier", "team", "cdhash"}
            or re.fullmatch(
                r"[A-Za-z0-9.-]+", identity.get("identifier", "")
            ) is None
            or re.fullmatch(
                r"[A-Za-z0-9.-]*", identity.get("team", "")
            ) is None
            or re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                identity.get("cdhash", ""),
            ) is None
        ):
            raise BuildError(
                f"native signed member identity {index} differs"
            )
        normalized.append(identity)
    if [row["identifier"] for row in normalized[:5]] != [
        PRODUCTION_DARWIN_SIGNING_IDENTIFIERS["launcher"],
        PRODUCTION_DARWIN_SIGNING_IDENTIFIERS["service"],
        PRODUCTION_DARWIN_SIGNING_IDENTIFIERS["extension"],
        PRODUCTION_DARWIN_SIGNING_IDENTIFIERS["installer"],
        PRODUCTION_DARWIN_SIGNING_IDENTIFIERS["source_bootstrap"],
    ] or any(row["team"] for row in normalized[:5]):
        raise BuildError("native ad-hoc signing roster differs")
    try:
        completed = subprocess.run(
            [
                executable_argv, (
                    "resume-publish-specialized-source-bootstrap-derived-fds"
                    if resume_specialized
                    else "prepare-publish-retained-specialized-source-bootstrap-derived-fds"
                    if specialized and source_bootstrap and retain_postcommit
                    else "prepare-publish-specialized-source-bootstrap-derived-fds"
                    if specialized and source_bootstrap
                    else "prepare-publish-retained-specialized-derived-fds"
                    if specialized and retain_postcommit
                    else "prepare-publish-specialized-derived-fds" if specialized
                    else "prepare-publish-retained-source-bootstrap-derived-fds"
                    if source_bootstrap and retain_postcommit
                    else "prepare-publish-source-bootstrap-derived-fds"
                    if source_bootstrap
                    else
                    "prepare-publish-retained-derived-fds"
                    if retain_postcommit and generation_id is None
                    else "prepare-publish-derived-fds"
                    if generation_id is None else "prepare-publish-fds"
                ),
                str(install_root_fd), str(staging_parent_fd),
                str(runtime_root_fd), str(receipt_output_fd),
                str(broker_plist_output_fd),
                str(custody_plist_output_fd), str(install_root),
                staged_name,
                *((generation_id,) if generation_id is not None else ()),
                projection_schema_sha256,
                protocol_schema_sha256, str(sys.version_info.micro),
                runtime_bindings["target_arch"],
                runtime_bindings["oci_image_reference"],
                runtime_bindings["oci_init_reference"],
                *(
                    runtime_bindings[field]
                    for field in RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS
                ),
                *(str(fd) for fd in member_fds),
                *((
                    str(image_member_rows_fd),
                    str(image_receipt_output_fd),
                    specialized_policy_self_sha256,
                    specialized_policy_bytes_sha256,
                ) if specialized else ()),
                *(
                    (
                        str(source_bootstrap_receipt_fd),
                        str(source_bootstrap_producer_verifier_key_fd),
                    ) if source_bootstrap else ()
                ),
                *(row["cdhash"] for row in normalized[:5]),
                normalized[5]["identifier"],
                normalized[5]["team"] or "-",
                normalized[5]["cdhash"],
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=_CLOSED_ENV, timeout=240,
            pass_fds=tuple(dict.fromkeys(descriptors)), close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("native retained prepare/publish failed") from exc
    if executable_fd is not None:
        _require_path_descriptor_rejoin(
            executable, executable_fd, "native install coordinator",
        )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise BuildError("native retained prepare/publish failed")


def _run_native_installed_receipt_cli(
    executable: Path, operation: str, *, install_root_fd: int,
    install_root: Path, successor_receipt_fd: int,
    prior_receipt_fd: int | None = None, executable_fd: int | None = None,
) -> None:
    """Validate/finalize/roll back one exact committed native receipt pair.

    The coordinator CLI consumes inherited descriptors.  A pathname is passed
    only as the already-authenticated root name needed by the receipt ABI; it
    is never used as the receipt authority.  Rollback's ``None`` predecessor
    means an exact previously-ABSENT installation, not an ambient lookup.
    """

    commands = {
        "validate": "validate-installed-fd",
        "finalize": "finalize-committed-fds",
        "rollback": "rollback-committed-fds",
    }
    if (
        operation not in commands
        or type(install_root_fd) is not int or install_root_fd < 3
        or type(successor_receipt_fd) is not int or successor_receipt_fd < 3
        or (prior_receipt_fd is not None and (
            type(prior_receipt_fd) is not int or prior_receipt_fd < 3
        ))
        or (operation != "rollback" and prior_receipt_fd is not None)
    ):
        raise BuildError("native installed-receipt operation differs")
    root = _canonical_absolute_path(install_root, "native install root")
    executable_argv = str(executable)
    descriptors = [install_root_fd, successor_receipt_fd]
    if executable_fd is not None:
        executable_argv = _retained_executable_argv(
            executable, executable_fd, "installed native coordinator",
        )
        descriptors.append(executable_fd)
    argv = [
        executable_argv, commands[operation], str(install_root_fd),
        str(successor_receipt_fd),
    ]
    if operation == "rollback":
        argv.append("-" if prior_receipt_fd is None else str(prior_receipt_fd))
        if prior_receipt_fd is not None:
            descriptors.append(prior_receipt_fd)
    argv.append(str(root))
    try:
        completed = subprocess.run(
            argv, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=_CLOSED_ENV, timeout=120,
            pass_fds=tuple(dict.fromkeys(descriptors)), close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError(
            f"native installed-receipt {operation} operation failed"
        ) from exc
    if executable_fd is not None:
        _require_path_descriptor_rejoin(
            executable, executable_fd, "installed native coordinator",
        )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise BuildError(
            f"native installed-receipt {operation} operation failed"
        )


def _run_native_evm_static_acquisition_cli(
    executable: Path, *, staged_generation_root_fd: int,
    medusa_archive_fd: int, medusa_sigstore_bundle_fd: int,
    solc_provider_index_fd: int, solc_binary_fd: int,
    executable_fd: int | None = None,
) -> bool:
    """Issue role-8/role-9 leaves from retained reviewed upstream inputs.

    The native coordinator owns authentication and creation beneath the
    retained private generation root.  This wrapper contributes no pathname,
    digest, policy, or network authority; it only transfers inherited FDs.
    """

    descriptors = [
        staged_generation_root_fd, medusa_archive_fd,
        medusa_sigstore_bundle_fd, solc_provider_index_fd, solc_binary_fd,
    ]
    if (
        any(type(fd) is not int or fd < 3 for fd in descriptors)
        or len(set(descriptors)) != len(descriptors)
    ):
        raise BuildError("native static EVM acquisition descriptor roster differs")
    executable_argv = str(executable)
    if executable_fd is not None:
        executable_argv = _retained_executable_argv(
            executable, executable_fd, "native source bootstrap coordinator",
        )
        descriptors.append(executable_fd)
    try:
        completed = subprocess.run(
            [
                executable_argv, "sign-evm-static-v1",
                str(staged_generation_root_fd), str(medusa_archive_fd),
                str(medusa_sigstore_bundle_fd), str(solc_provider_index_fd),
                str(solc_binary_fd),
            ],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=_CLOSED_ENV, timeout=240,
            pass_fds=tuple(descriptors), close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("native static EVM acquisition failed") from exc
    if executable_fd is not None:
        _require_path_descriptor_rejoin(
            executable, executable_fd, "native source bootstrap coordinator",
        )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise BuildError("native static EVM acquisition failed")
    return True


def _run_native_fixed_role_acquisition_cli(
    executable: Path, *, source_freeze: dict[str, Any], executable_fd: int,
    staged_generation_root_fd: int, inputs: tuple[Any, ...],
    timeout_seconds: int = 1800,
) -> tuple[Any, ...]:
    """Issue roles 0-4/7/10 through the frozen descriptor-custody adapter.

    The adapter, not this builder, owns the fixed argc-31 wire and the exact
    post-publication replay.  Loading it from the already-validated source
    freeze prevents an ambient ``PYTHONPATH`` module from becoming installer
    authority.  The returned rows still own their retained descriptors.
    """

    if (
        type(source_freeze) is not dict
        or not isinstance(executable, Path) or not executable.is_absolute()
        or type(executable_fd) is not int or executable_fd < 3
        or type(staged_generation_root_fd) is not int
        or staged_generation_root_fd < 3
        or type(inputs) is not tuple or len(inputs) != 7
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 3600
    ):
        raise BuildError("native fixed-role acquisition arguments differ")
    module = _load_frozen_source_module(
        "_plamen_frozen_native_fixed_role_acquisition",
        "native_fixed_role_acquisition", source_freeze,
    )
    runner = getattr(module, "run_native_fixed_role_issue_cli", None)
    if not callable(runner):
        raise BuildError("frozen native fixed-role acquisition adapter is absent")
    try:
        result = runner(
            executable_fd=executable_fd,
            executable_path=(str(executable) if sys.platform == "darwin" else None),
            staged_generation_root_fd=staged_generation_root_fd,
            inputs=inputs, timeout_seconds=timeout_seconds,
        )
    except BaseException as exc:
        raise BuildError(
            "native fixed-role acquisition failed: "
            + type(exc).__name__
        ) from None
    if type(result) is not tuple or len(result) != 7:
        raise BuildError("native fixed-role acquisition returned no authority")
    return result


def _run_native_source_bootstrap_issue_cli(
    executable: Path, *, runtime_root_fd: int, python_fd: int,
    transform_fd: int, producer_verifier_key_fd: int,
    composition_manifest_fd: int, role_fds: list[tuple[int, int, int]],
    output_pairs: list[tuple[int, int]], scratch_fds: list[int],
    coordinator_receipt_pair: tuple[int, int],
    grouped_operation_pair: tuple[int, int],
    operation_terminal_pair: tuple[int, int],
    executable_fd: int | None = None,
) -> bool:
    """Issue the complete role-10 authority through the fixed argc-80 ABI."""

    if (
        type(role_fds) is not list or len(role_fds) != _OPERATION4_ROLE_COUNT
        or any(type(row) is not tuple or len(row) != 3 for row in role_fds)
        or type(output_pairs) is not list or len(output_pairs) != 5
        or any(type(row) is not tuple or len(row) != 2 for row in output_pairs)
        or type(scratch_fds) is not list or len(scratch_fds) != 24
        or type(coordinator_receipt_pair) is not tuple
        or len(coordinator_receipt_pair) != 2
        or type(grouped_operation_pair) is not tuple
        or len(grouped_operation_pair) != 2
        or type(operation_terminal_pair) is not tuple
        or len(operation_terminal_pair) != 2
    ):
        raise BuildError("native source-bootstrap descriptor shape differs")
    descriptors = [
        runtime_root_fd, python_fd, transform_fd,
        producer_verifier_key_fd, composition_manifest_fd,
        *(fd for row in role_fds for fd in row),
        *(fd for row in output_pairs for fd in row),
        *scratch_fds, *coordinator_receipt_pair,
        *grouped_operation_pair, *operation_terminal_pair,
    ]
    if (
        len(descriptors) != 78
        or any(type(fd) is not int or fd < 3 for fd in descriptors)
        or len(set(descriptors)) != len(descriptors)
    ):
        raise BuildError("native source-bootstrap descriptor roster differs")
    executable_argv = str(executable)
    pass_descriptors = list(descriptors)
    if executable_fd is not None:
        executable_argv = _retained_executable_argv(
            executable, executable_fd,
            "native source-bootstrap coordinator",
        )
        pass_descriptors.append(executable_fd)
    try:
        completed = subprocess.run(
            [executable_argv, "issue-v1", *(str(fd) for fd in descriptors)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=_CLOSED_ENV, timeout=300,
            pass_fds=tuple(pass_descriptors), close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("native source-bootstrap issuance failed") from exc
    if executable_fd is not None:
        _require_path_descriptor_rejoin(
            executable, executable_fd,
            "native source-bootstrap coordinator",
        )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise BuildError("native source-bootstrap issuance failed")
    return True


def _run_native_backend_receipt_signer_cli(
    executable: Path, *, public_key_pair: tuple[int, int],
    backend_rows: list[tuple[int, int, int, int, int]],
    executable_fd: int | None = None,
) -> bool:
    """Sign the Codex/Claude generation receipts under one native key."""

    if (
        type(public_key_pair) is not tuple or len(public_key_pair) != 2
        or type(backend_rows) is not list or len(backend_rows) != 2
        or any(type(row) is not tuple or len(row) != 5 for row in backend_rows)
    ):
        raise BuildError("native backend signer descriptor shape differs")
    descriptors = [
        *public_key_pair, *(fd for row in backend_rows for fd in row),
    ]
    if (
        len(descriptors) != 12
        or any(type(fd) is not int or fd < 3 for fd in descriptors)
        or len(set(descriptors)) != len(descriptors)
    ):
        raise BuildError("native backend signer descriptor roster differs")
    executable_argv = str(executable)
    pass_descriptors = list(descriptors)
    if executable_fd is not None:
        executable_argv = _retained_executable_argv(
            executable, executable_fd,
            "native source-bootstrap coordinator",
        )
        pass_descriptors.append(executable_fd)
    try:
        completed = subprocess.run(
            [executable_argv, "sign-backends-v1",
             *(str(fd) for fd in descriptors)],
            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=_CLOSED_ENV, timeout=300,
            pass_fds=tuple(pass_descriptors), close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("native backend receipt signing failed") from exc
    if executable_fd is not None:
        _require_path_descriptor_rejoin(
            executable, executable_fd,
            "native source-bootstrap coordinator",
        )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise BuildError("native backend receipt signing failed")
    return True


def _darwin_ad_hoc_code_identity(
    path: Path, label: str, *, retained_fd: int | None = None,
) -> dict[str, str]:
    if retained_fd is not None:
        _require_path_descriptor_rejoin(path, retained_fd, label)
    _run_profile_observation(
        [
            "/usr/bin/codesign", "--verify", "--strict", "--verbose=4",
            str(path),
        ],
        label=f"{label} strict code signature",
    )
    if retained_fd is not None:
        _require_path_descriptor_rejoin(path, retained_fd, label)
    output = _run_profile_observation(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
        label=f"{label} code identity",
    ).decode("utf-8", "strict")
    if retained_fd is not None:
        _require_path_descriptor_rejoin(path, retained_fd, label)
    fields: dict[str, str] = {}
    for line in output.splitlines():
        for key in ("Identifier", "TeamIdentifier", "CDHash"):
            if line.startswith(key + "="):
                if key in fields:
                    raise BuildError(f"{label} code identity is ambiguous")
                fields[key] = line[len(key) + 1:]
    if fields.get("TeamIdentifier") == "not set":
        fields["TeamIdentifier"] = ""
    if (
        set(fields) != {"Identifier", "TeamIdentifier", "CDHash"}
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", fields["CDHash"])
        is None
    ):
        raise BuildError(f"{label} ad-hoc code identity differs")
    return {
        "identifier": fields["Identifier"],
        "team": fields["TeamIdentifier"], "cdhash": fields["CDHash"],
    }


def _render_operation4_fixed_policy_source(rows: object) -> bytes:
    """Render the derived strong operation-4 policy translation unit.

    The input rows are exact retained acquisition products.  This renderer is
    deliberately independent of the C helper's weak fail-closed definition;
    it recomputes the native big-endian roster commitment and emits only the
    one strong symbol linked into the signed role-10 coordinator.
    """

    fields = {
        "role", "identity_mode", "receipt_validator", "payload_size",
        "source_manifest_size", "semantic_receipt_size", "payload_sha256",
        "source_manifest_sha256", "semantic_receipt_sha256",
        "policy_sha256", "receipt_schema",
    }
    if type(rows) is not list or len(rows) != _OPERATION4_ROLE_COUNT:
        raise BuildError("operation-4 fixed policy roster differs")
    normalized: list[dict[str, Any]] = []
    roster = hashlib.sha256()
    roster.update(b"PLAMEN-NATIVE-OPERATION4-POLICY-ROSTER-V1\0")
    roster.update(struct.pack(">II", 1, _OPERATION4_ROLE_COUNT))
    for role, value in enumerate(rows):
        if type(value) is not dict or set(value) != fields:
            raise BuildError("operation-4 fixed policy row differs")
        schema = value.get("receipt_schema")
        sizes = tuple(value.get(name) for name in (
            "payload_size", "source_manifest_size", "semantic_receipt_size",
        ))
        hashes = tuple(value.get(name) for name in (
            "payload_sha256", "source_manifest_sha256",
            "semantic_receipt_sha256", "policy_sha256",
        ))
        if (
            value.get("role") != role
            or value.get("identity_mode") != _OPERATION4_IDENTITY_MODES[role]
            or value.get("receipt_validator")
            != _OPERATION4_RECEIPT_VALIDATORS[role]
            or type(schema) is not str
            or schema != _OPERATION4_POLICY_SCHEMAS[role]
            or not 0 < len(schema.encode("ascii")) < 96
            or any(type(size) is not int or size < 0 for size in sizes)
            or any(
                type(digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for digest in hashes
            )
            or hashes[3] == "0" * 64
        ):
            raise BuildError("operation-4 fixed policy row differs")
        latest = role in (5, 6)
        if latest:
            if any(sizes) or any(digest != "0" * 64 for digest in hashes[:3]):
                raise BuildError("operation-4 dynamic backend policy differs")
        elif any(size <= 0 for size in sizes) or any(
            digest == "0" * 64 for digest in hashes[:3]
        ):
            raise BuildError("operation-4 static policy identity differs")
        scalar = struct.pack(
            ">HHHHQQQ", role, value["identity_mode"],
            value["receipt_validator"], 0, *sizes,
        )
        schema_raw = schema.encode("ascii")
        roster.update(scalar)
        for digest in hashes:
            roster.update(bytes.fromhex(digest))
        roster.update(struct.pack(">H", len(schema_raw)))
        roster.update(schema_raw)
        normalized.append(dict(value))

    def byte_array(raw: bytes) -> str:
        return "{" + ",".join(f"0x{byte:02x}" for byte in raw) + "}"

    rendered_rows = []
    for row in normalized:
        schema = row["receipt_schema"].encode("ascii") + b"\0"
        rendered_rows.append(
            "        {"
            f".role={row['role']}U,.identity_mode={row['identity_mode']}U,"
            f".receipt_validator={row['receipt_validator']}U,.reserved=0U,"
            f".payload_size={row['payload_size']}ULL,"
            f".source_manifest_size={row['source_manifest_size']}ULL,"
            f".semantic_receipt_size={row['semantic_receipt_size']}ULL,"
            f".payload_sha256={byte_array(bytes.fromhex(row['payload_sha256']))},"
            ".source_manifest_sha256="
            f"{byte_array(bytes.fromhex(row['source_manifest_sha256']))},"
            ".semantic_receipt_sha256="
            f"{byte_array(bytes.fromhex(row['semantic_receipt_sha256']))},"
            f".policy_sha256={byte_array(bytes.fromhex(row['policy_sha256']))},"
            f".receipt_schema={byte_array(schema)}"
            "}"
        )
    source = (
        '#include "plamen_native_operation4_helper_v1.h"\n\n'
        "const struct plamen_native_operation4_fixed_policy_v1\n"
        "plamen_native_operation4_generated_policy_v1 = {\n"
        "    .version=1U,.role_count=11U,\n"
        f"    .roster_sha256={byte_array(roster.digest())},\n"
        "    .rows={\n" + ",\n".join(rendered_rows) + "\n    }\n};\n"
    )
    return source.encode("ascii")


def _require_path_descriptor_rejoin(path: Path, descriptor: int, label: str) -> os.stat_result:
    """Require an unavoidable named tool input to still name a retained vnode."""

    try:
        opened = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise BuildError(f"{label} pathname authority is unavailable") from exc
    if not _same_stat(opened, named):
        raise BuildError(f"{label} pathname authority differs")
    return opened


def _clang_retained_vfs_overlay(
    virtual_files: dict[Path, int],
) -> bytes:
    """Map every compiler-visible source leaf to its inherited descriptor."""

    if not virtual_files:
        raise BuildError("retained compiler source roster is empty")
    roots: list[dict[str, str]] = []
    seen_fds: set[int] = set()
    for path, descriptor in sorted(
        virtual_files.items(), key=lambda item: os.fsencode(item[0]),
    ):
        if (
            not path.is_absolute() or type(descriptor) is not int
            or descriptor < 3 or descriptor in seen_fds
        ):
            raise BuildError("retained compiler source authority differs")
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink not in {0, 1}
            or (
                info.st_uid != os.geteuid()
                and not (info.st_uid == 0 and info.st_nlink == 1)
            )
            or stat.S_IMODE(info.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise BuildError("retained compiler source is not a regular vnode")
        seen_fds.add(descriptor)
        roots.append({
            "type": "file", "name": os.fspath(path),
            "external-contents": _fd_path(descriptor),
        })
    return json.dumps({
        "version": 0, "case-sensitive": "true",
        "use-external-names": False, "roots": roots,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _select_darwin_release_compile_rows(
    artifact_kinds: object | None, operation4_policy_rows: object | None,
) -> tuple[tuple[dict[str, Any], ...], bytes | None]:
    """Select one canonical compile tranche without crossing the op4 cycle."""

    all_compile_rows = [*PRODUCTION_DARWIN_LINK_ROSTER, {
        "artifact": "plamen-native-generation-builder-v2",
        "compile_flags": (
            "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-DPLAMEN_NATIVE_BUILDER_V2_MAIN",
        ),
        "flags": (), "init_symbol": None,
        "kind": "retained-generation-stage-helper",
        "source_roles": ("native_builder",),
    }]
    available_kinds = tuple(row["kind"] for row in all_compile_rows)
    if artifact_kinds is None:
        selected_kinds = available_kinds
    elif (
        type(artifact_kinds) is tuple and artifact_kinds
        and all(type(kind) is str for kind in artifact_kinds)
        and len(set(artifact_kinds)) == len(artifact_kinds)
        and set(artifact_kinds) <= set(available_kinds)
    ):
        selected_kinds = artifact_kinds
    else:
        raise BuildError("release artifact selection differs")
    compile_rows = tuple(
        row for row in all_compile_rows if row["kind"] in selected_kinds
    )
    if tuple(row["kind"] for row in compile_rows) != tuple(
        kind for kind in available_kinds if kind in selected_kinds
    ) or selected_kinds != tuple(row["kind"] for row in compile_rows):
        raise BuildError("release artifact selection order differs")
    needs_operation4_policy = any(
        row["kind"] in PRODUCTION_OPERATION4_POLICY_CONSUMERS
        for row in compile_rows
    )
    if needs_operation4_policy:
        if operation4_policy_rows is None:
            raise BuildError("operation-4 fixed policy rows are absent")
        generated_policy = _render_operation4_fixed_policy_source(
            operation4_policy_rows,
        )
    elif operation4_policy_rows is not None:
        raise BuildError("unused operation-4 policy authority")
    else:
        generated_policy = None
    return compile_rows, generated_policy


def _compile_darwin_source_release_artifacts(
    workspace: Path, workspace_fd: int, source_freeze: dict[str, Any], *,
    operation4_policy_rows: object | None,
    artifact_kinds: object | None = None,
) -> dict[str, dict[str, Any]]:
    """Compile/sign one canonical native tranche from retained sources."""

    expected = {
        row["role"]: row for row in source_freeze.get("sources", [])
        if type(row) is dict
    }
    if set(expected) != {
        role for role, _relative in PRODUCTION_DARWIN_SOURCE_ROSTER
    }:
        raise BuildError("production source freeze is incomplete for compilation")
    compile_rows, generated_policy = _select_darwin_release_compile_rows(
        artifact_kinds, operation4_policy_rows,
    )
    metadata: dict[str, Any]
    state: dict[str, Any] = {}
    source_fds: dict[str, int] = {}
    snapshot_file_fds: dict[str, int] = {}
    python_header_fds: list[int] = []
    snapshot_directory_fds: dict[tuple[str, ...], int] = {}
    outputs: dict[str, dict[str, Any]] = {}
    generated_fd = overlay_fd = -1
    try:
        workspace = _canonical_absolute_path(workspace, "release build workspace")
        # Darwin's Clang canonicalizes a top-level input through the system
        # ``/var -> /private/var`` alias before consulting the VFS overlay.
        # Resolve only this already-retained private directory and immediately
        # rejoin the resolved name to its descriptor; otherwise every retained
        # virtual source appears absent even though the overlay is valid.
        resolved_workspace = Path(os.path.realpath(workspace))
        if not resolved_workspace.is_absolute():
            raise BuildError("release build workspace resolution differs")
        _require_path_descriptor_rejoin(
            resolved_workspace, workspace_fd, "resolved release build workspace",
        )
        workspace = resolved_workspace
        workspace_info = _require_path_descriptor_rejoin(
            workspace, workspace_fd, "release build workspace",
        )
        if (
            not stat.S_ISDIR(workspace_info.st_mode)
            or workspace_info.st_uid != os.geteuid()
            or stat.S_IMODE(workspace_info.st_mode) != 0o700
        ):
            raise BuildError("release build workspace is not private")
        metadata, state = _metadata(False, test_production_shape=True)
        for role, relative in PRODUCTION_DARWIN_SOURCE_ROSTER:
            fd, resolved, identity = _open_retained_regular(
                REPOSITORY_ROOT / relative, f"release compile source {role}"
            )
            if (
                resolved != REPOSITORY_ROOT / relative
                or identity["sha256"] != expected[role]["sha256"]
                or identity["size"] != expected[role]["size"]
            ):
                os.close(fd)
                raise BuildError(f"release compile source {role} differs")
            source_fds[role] = fd
        snapshot_root = workspace / "source-snapshot"
        snapshot_directory_fds[()] = _mkdir_new(
            workspace_fd, "source-snapshot"
        )
        for role, relative in PRODUCTION_DARWIN_SOURCE_ROSTER:
            parts = PurePosixPath(relative).parts
            parent_key: tuple[str, ...] = ()
            for component in parts[:-1]:
                child_key = (*parent_key, component)
                if child_key not in snapshot_directory_fds:
                    snapshot_directory_fds[child_key] = _mkdir_new(
                        snapshot_directory_fds[parent_key], component
                    )
                parent_key = child_key
            raw = _read_fd(
                source_fds[role], PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                f"frozen release snapshot {role}",
            )
            copied_fd, copied_identity = _write_new_retained(
                snapshot_directory_fds[parent_key], parts[-1], raw, 0o400,
            )
            if (
                copied_identity["sha256"] != expected[role]["sha256"]
                or copied_identity["size"] != expected[role]["size"]
            ):
                os.close(copied_fd)
                raise BuildError(f"frozen release snapshot {role} differs")
            # The virtual name must exist for Darwin Clang to admit a top-level
            # input.  It is not content authority: the retained VFS overlay
            # redirects the name to this exact descriptor, and the frozen
            # private directory prevents ordinary replacement.  A substituted
            # named vnode is therefore ignored rather than compiled.
            snapshot_file_fds[role] = copied_fd
        generated_name = "plamen_native_operation4_generated_policy_v1.c"
        if generated_policy is not None:
            generated_parent = snapshot_directory_fds[("native", "darwin")]
            generated_fd, generated_identity = _write_new_retained(
                generated_parent, generated_name, generated_policy, 0o400,
            )
            if (
                generated_identity["size"] != len(generated_policy)
                or generated_identity["sha256"]
                != hashlib.sha256(generated_policy).hexdigest()
            ):
                raise BuildError("derived operation-4 policy source differs")
            # As above, Clang requires the generated virtual input name to
            # exist; the overlay binds its content to ``generated_fd``.
        for key in sorted(snapshot_directory_fds, key=len, reverse=True):
            descriptor = snapshot_directory_fds[key]
            os.fchmod(descriptor, 0o500); os.fsync(descriptor)
        os.fsync(workspace_fd)
        include_flags = [
            "-I" + str(snapshot_root / "native" / "include"),
            "-I" + str(snapshot_root / "native" / "posix"),
            "-I" + str(snapshot_root / "native" / "darwin"),
            "-I" + str(snapshot_root / "native" / "cpython"),
        ]
        python_includes = [
            "-I" + str(root) for root, _commitment, _rows
            in state["include_roots"]
        ]
        virtual_files = {
            snapshot_root / expected[role]["path"]: descriptor
            for role, descriptor in snapshot_file_fds.items()
        }
        if generated_fd >= 0:
            virtual_files[
                snapshot_root / "native" / "darwin" / generated_name
            ] = generated_fd
        for include_root, _commitment, rows in state["include_roots"]:
            include_root = Path(include_root)
            for header in rows:
                descriptor, resolved, identity = _open_retained_regular(
                    include_root / header["path"],
                    "production Python compile header",
                )
                if (
                    resolved != include_root / header["path"]
                    or identity["size"] != header["size"]
                    or identity["mode"] != header["mode"]
                    or identity["uid"] != header["uid"]
                    or identity["gid"] != header["gid"]
                    or identity["sha256"] != header["sha256"]
                ):
                    os.close(descriptor)
                    raise BuildError("production Python compile header differs")
                python_header_fds.append(descriptor)
                virtual_files[resolved] = descriptor
        overlay = _clang_retained_vfs_overlay(virtual_files)
        overlay_fd, overlay_identity = _write_new_retained(
            workspace_fd, ".clang-retained-vfs-overlay.json", overlay, 0o400,
        )
        if (
            overlay_identity["size"] != len(overlay)
            or overlay_identity["sha256"] != hashlib.sha256(overlay).hexdigest()
        ):
            raise BuildError("retained compiler VFS overlay differs")
        os.unlink(".clang-retained-vfs-overlay.json", dir_fd=workspace_fd)
        os.fsync(workspace_fd)
        compiler_input_fds = (
            overlay_fd,
            *((generated_fd,) if generated_fd >= 0 else ()),
            *snapshot_file_fds.values(), *python_header_fds,
        )
        retained_vfs_flags = ["-ivfsoverlay", _fd_path(overlay_fd)]
        for row in compile_rows:
            artifact_name = row["artifact"].replace(
                "{EXT_SUFFIX}", ".cpython-312-darwin.so"
            )
            output_fd = os.open(
                artifact_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600, dir_fd=workspace_fd,
            )
            output_path = workspace / artifact_name
            c_roles = [
                role for role in row["source_roles"]
                if role in source_fds and expected[role]["path"].endswith(".c")
            ]
            swift_roles = [
                role for role in row["source_roles"]
                if role in source_fds
                and expected[role]["path"].endswith(".swift")
            ]
            if not c_roles:
                os.close(output_fd)
                raise BuildError(f"release artifact {artifact_name} has no source")
            if swift_roles:
                if (
                    row["kind"] != "retained-source-bootstrap-coordinator"
                    or swift_roles != [
                        "darwin_backend_receipt_signer_swift",
                        "darwin_evm_static_acquisition_swift",
                    ]
                ):
                    os.close(output_fd)
                    raise BuildError("release Swift source roster differs")
                object_fds: list[int] = []
                object_names: list[str] = []
                swiftc_fd = -1
                try:
                    object_sources = [
                        *(snapshot_root / expected[role]["path"]
                          for role in c_roles),
                        snapshot_root / "native" / "darwin" / generated_name,
                    ]
                    for ordinal, object_source in enumerate(object_sources):
                        object_name = f"{artifact_name}.part-{ordinal}.o"
                        object_fd = os.open(
                            object_name,
                            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                            | os.O_NOFOLLOW, 0o600, dir_fd=workspace_fd,
                        )
                        object_fds.append(object_fd)
                        object_names.append(object_name)
                        compile_command = [
                            str(state["compiler"]), *state["compiler_suffix"],
                            *row["compile_flags"],
                            "-Wno-deprecated-declarations", "-x", "c", "-c",
                            *state["sdk_flags"], *retained_vfs_flags,
                            *include_flags,
                            str(object_source), "-o", _fd_path(object_fd),
                        ]
                        compiled = subprocess.run(
                            compile_command, check=False,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=_CLOSED_ENV,
                            timeout=180,
                            pass_fds=(
                                state["compiler_fd"], object_fd,
                                *compiler_input_fds,
                            ),
                            close_fds=True,
                            executable=_retained_executable_argv(
                                Path(state["compiler"]), state["compiler_fd"],
                                "retained release compiler",
                            ),
                        )
                        _require_path_descriptor_rejoin(
                            Path(state["compiler"]), state["compiler_fd"],
                            "retained release compiler",
                        )
                        if compiled.returncode != 0 or len(
                            compiled.stdout
                        ) > MAX_COMPILER_OUTPUT_BYTES:
                            raise BuildError(
                                "release role10 C compilation failed: "
                                + compiled.stdout.decode(
                                    "utf-8", "replace"
                                )[:4096]
                            )
                        os.fsync(object_fd)
                    swiftc_fd, swiftc_path, swiftc_identity = (
                        _open_retained_regular(
                            Path("/usr/bin/swiftc"),
                            "production Swift compiler",
                        )
                    )
                    swiftc_info = os.fstat(swiftc_fd)
                    if (
                        swiftc_path != Path("/usr/bin/swiftc")
                        or swiftc_identity["uid"] != 0
                        or swiftc_identity["mode"] & 0o022
                        or not swiftc_identity["mode"] & 0o111
                        or swiftc_info.st_nlink < 1
                    ):
                        raise BuildError("production Swift compiler differs")
                    swift_sources = [
                        snapshot_root / expected[role]["path"]
                        for role in swift_roles
                    ]
                    object_paths = [workspace / name for name in object_names]
                    for role, source_path in zip(
                        swift_roles, swift_sources, strict=True,
                    ):
                        _require_path_descriptor_rejoin(
                            source_path, snapshot_file_fds[role],
                            "retained Swift release source",
                        )
                    for object_path, object_fd in zip(
                        object_paths, object_fds, strict=True,
                    ):
                        _require_path_descriptor_rejoin(
                            object_path, object_fd,
                            "retained role10 object",
                        )
                    # Swift's driver classifies inputs and publishes its output
                    # by pathname; it rejects `/dev/fd` object/output names.
                    # This is the same unavoidable private-path boundary as
                    # codesign below.  Retain every input across the call and
                    # rejoin it immediately afterwards; the signed output is
                    # then reopened and retained before handoff.
                    os.close(output_fd)
                    output_fd = -1
                    command = [
                        str(swiftc_path), "-warnings-as-errors",
                        "-parse-as-library",
                        *(str(path) for path in swift_sources),
                        *(str(path) for path in object_paths),
                        "-Xlinker", "-framework", "-Xlinker", "Foundation",
                        "-Xlinker", "-framework", "-Xlinker", "CryptoKit",
                        "-Xlinker", "-framework", "-Xlinker", "Security",
                        "-Xlinker", "-lz",
                        "-Xlinker", "-lproc", "-o", str(output_path),
                    ]
                    completed = subprocess.run(
                        command, check=False, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        env=_CLOSED_ENV, timeout=180,
                        pass_fds=(swiftc_fd,
                                  *(snapshot_file_fds[role]
                                    for role in swift_roles),
                                  *object_fds), close_fds=True,
                        executable=_retained_executable_argv(
                            swiftc_path, swiftc_fd,
                            "retained production Swift compiler",
                        ),
                    )
                    if (
                        not _same_stat(swiftc_info, os.fstat(swiftc_fd))
                        or not _same_stat(
                            swiftc_info,
                            _require_path_descriptor_rejoin(
                                swiftc_path, swiftc_fd,
                                "retained production Swift compiler",
                            ),
                        )
                    ):
                        raise BuildError("production Swift compiler drifted")
                    for role, source_path in zip(
                        swift_roles, swift_sources, strict=True,
                    ):
                        _require_path_descriptor_rejoin(
                            source_path, snapshot_file_fds[role],
                            "retained Swift release source",
                        )
                    for object_path, object_fd in zip(
                        object_paths, object_fds, strict=True,
                    ):
                        _require_path_descriptor_rejoin(
                            object_path, object_fd,
                            "retained role10 object",
                        )
                    _require_path_descriptor_rejoin(
                        workspace, workspace_fd, "release build workspace",
                    )
                    if completed.returncode != 0 or len(
                        completed.stdout
                    ) > MAX_COMPILER_OUTPUT_BYTES:
                        raise BuildError(
                            "release role10 Swift link failed: "
                            + completed.stdout.decode(
                                "utf-8", "replace"
                            )[:4096]
                        )
                    output_fd = os.open(
                        artifact_name,
                        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=workspace_fd,
                    )
                finally:
                    if swiftc_fd >= 0:
                        os.close(swiftc_fd)
                    for object_fd in object_fds:
                        os.close(object_fd)
                    for object_name in object_names:
                        try:
                            os.unlink(object_name, dir_fd=workspace_fd)
                        except FileNotFoundError:
                            pass
            else:
                command = [
                    str(state["compiler"]), *state["compiler_suffix"],
                    *row["compile_flags"], "-x", "c", *state["sdk_flags"],
                    *retained_vfs_flags, *include_flags,
                    *(python_includes if row["kind"] == "cpython-extension" else ()),
                    *(str(snapshot_root / expected[role]["path"])
                      for role in c_roles),
                    *((str(
                        snapshot_root / "native" / "darwin" / generated_name
                    ),) if row["kind"] in PRODUCTION_OPERATION4_POLICY_CONSUMERS
                    else ()),
                    *row["flags"], "-o", _fd_path(output_fd),
                ]
                completed = subprocess.run(
                    command, check=False, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    env=_CLOSED_ENV, timeout=180,
                    pass_fds=(
                        state["compiler_fd"], output_fd, *compiler_input_fds,
                    ),
                    close_fds=True,
                    executable=_retained_executable_argv(
                        Path(state["compiler"]), state["compiler_fd"],
                        "retained release compiler",
                    ),
                )
                _require_path_descriptor_rejoin(
                    Path(state["compiler"]), state["compiler_fd"],
                    "retained release compiler",
                )
            if completed.returncode != 0 or len(
                completed.stdout
            ) > MAX_COMPILER_OUTPUT_BYTES:
                os.close(output_fd)
                raise BuildError(
                    f"release artifact {artifact_name} compilation failed: "
                    + completed.stdout.decode("utf-8", "replace")[:4096]
            )
            os.fsync(output_fd)
            compiled_info = os.fstat(output_fd)
            _require_path_descriptor_rejoin(
                workspace, workspace_fd, "release build workspace",
            )
            compiled_named = os.stat(
                artifact_name, dir_fd=workspace_fd, follow_symlinks=False,
            )
            if not _same_stat(compiled_info, compiled_named):
                os.close(output_fd)
                raise BuildError(f"release artifact {artifact_name} was replaced")
            # codesign publishes a replacement vnode.  Retire the unsigned
            # writer first, then reopen and retain the signed private-stage
            # leaf; no unsigned descriptor is allowed into the handoff.
            os.close(output_fd)
            output_fd = -1
            identifier = (
                PRODUCTION_DARWIN_SIGNING_IDENTIFIERS[
                    "extension" if row["kind"] == "cpython-extension"
                    else "service" if row["kind"] == "launchd-xpc-service"
                    else "launcher" if row["kind"] == "fixed-native-entrypoint"
                    else "source_bootstrap"
                    if row["kind"] == "retained-source-bootstrap-coordinator"
                    else "installer"
                ]
            )
            signed = subprocess.run(
                [
                    "/usr/bin/codesign", "--force", "--sign", "-",
                    "--identifier", identifier, "--timestamp=none",
                    str(output_path),
                ],
                check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=_CLOSED_ENV, timeout=60,
            )
            if signed.returncode != 0 or signed.stdout or len(
                signed.stderr
            ) > MAX_COMPILER_OUTPUT_BYTES:
                raise BuildError(f"release artifact {artifact_name} signing failed")
            _require_path_descriptor_rejoin(
                workspace, workspace_fd, "release build workspace",
            )
            output_fd = os.open(
                artifact_name, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=workspace_fd,
            )
            mode = 0o400 if row["kind"] == "cpython-extension" else 0o500
            os.fchmod(output_fd, mode); os.fsync(output_fd)
            info = os.fstat(output_fd)
            named = os.stat(
                artifact_name, dir_fd=workspace_fd, follow_symlinks=False,
            )
            code = _darwin_ad_hoc_code_identity(
                output_path, artifact_name, retained_fd=output_fd,
            )
            if (
                not _same_stat(info, named) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode
                or code["identifier"] != identifier or code["team"] != ""
            ):
                os.close(output_fd)
                raise BuildError(f"release artifact {artifact_name} drifted")
            os.close(output_fd)
            output_fd = os.open(
                artifact_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=workspace_fd,
            )
            retained = os.fstat(output_fd)
            if not _same_stat(info, retained):
                os.close(output_fd)
                raise BuildError(
                    f"release artifact {artifact_name} retained vnode differs"
                )
            outputs[row["kind"]] = {
                "fd": output_fd, "path": output_path,
                "identity": _identity(
                    retained, _sha256_fd(output_fd, retained.st_size),
                ),
                "code_identity": code, "artifact": artifact_name,
            }
        for role, descriptor in source_fds.items():
            row = expected[role]
            info = os.fstat(descriptor)
            if (
                info.st_size != row["size"]
                or _sha256_fd(descriptor, info.st_size) != row["sha256"]
            ):
                raise BuildError(f"release compile source {role} drifted")
        _require_path_descriptor_rejoin(
            workspace, workspace_fd, "release build workspace",
        )
        return outputs
    except BaseException:
        for output in outputs.values():
            descriptor = output.get("fd", -1)
            if isinstance(descriptor, int) and descriptor >= 0:
                os.close(descriptor)
        raise
    finally:
        for descriptor in source_fds.values():
            os.close(descriptor)
        for descriptor in snapshot_file_fds.values():
            os.close(descriptor)
        for descriptor in python_header_fds:
            os.close(descriptor)
        if generated_fd >= 0:
            os.close(generated_fd)
        if overlay_fd >= 0:
            os.close(overlay_fd)
        for descriptor in snapshot_directory_fds.values():
            os.close(descriptor)
        _close_build_state(state)


def _load_exact_production_source_freeze() -> dict[str, Any]:
    """Load the final freeze and replay every row before executing its code."""

    descriptor = -1
    try:
        descriptor, resolved, identity = _open_retained_regular(
            PRODUCTION_SOURCE_FREEZE_MANIFEST,
            "production source freeze manifest",
        )
        if resolved != PRODUCTION_SOURCE_FREEZE_MANIFEST:
            raise BuildError("production source freeze manifest is aliased")
        raw = _read_fd(
            descriptor, PRODUCTION_SOURCE_FREEZE_MAX_BYTES,
            "production source freeze manifest",
        )
        decoded = decode_production_source_freeze_manifest(raw)
        decoded["manifest_sha256"] = identity["sha256"]
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    for row in decoded["sources"]:
        source_fd = -1
        try:
            source_fd, resolved, observed = _open_retained_regular(
                REPOSITORY_ROOT / row["path"],
                f"frozen source {row['role']}",
            )
            if (
                resolved != REPOSITORY_ROOT / row["path"]
                or observed["sha256"] != row["sha256"]
                or observed["size"] != row["size"]
            ):
                raise BuildError(f"frozen source {row['role']} differs")
        finally:
            if source_fd >= 0:
                os.close(source_fd)
    _validate_frozen_runtime_source_projection(decoded)
    return decoded


def _load_frozen_source_module(
    module_name: str, source_role: str, source_freeze: dict[str, Any],
) -> Any:
    rows = {
        row["role"]: row for row in source_freeze["sources"]
        if type(row) is dict
    }
    row = rows.get(source_role)
    if row is None or not row["path"].endswith(".py"):
        raise BuildError(f"frozen module role {source_role} is unavailable")
    path = REPOSITORY_ROOT / row["path"]
    descriptor = -1
    try:
        descriptor, resolved, observed = _open_retained_regular(
            path, f"frozen module {module_name}",
        )
        if (
            resolved != path
            or observed["sha256"] != row["sha256"]
            or observed["size"] != row["size"]
        ):
            raise BuildError(f"frozen module {module_name} differs")
        raw = _read_fd(
            descriptor, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
            f"frozen module {module_name}",
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    module = ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        code = compile(raw, str(path), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException as exc:
        raise BuildError(
            f"frozen module {module_name} cannot be loaded: {type(exc).__name__}"
        ) from None
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    return module


def _bind_retained_backend_generation(
    *, source_freeze: dict[str, Any], receipt: dict[str, Any],
    policy: dict[str, Any], policy_sha256: str, verifier: Any,
    payload_fd: int, semantic_receipt_fd: int, source_manifest_fd: int,
    verifier_public_key_fd: int,
) -> Any:
    """Admit one install-resolved backend without reopening any path.

    Resolution and materialization happen inside the install transaction.  The
    frozen v2 authority module independently authenticates the retained
    payload, semantic receipt, source manifest, and verifier key descriptors.
    This wrapper deliberately returns that opaque retained object unchanged so
    the native stage can publish those same vnodes inside the generation.
    """

    descriptors = (
        payload_fd, semantic_receipt_fd, source_manifest_fd,
        verifier_public_key_fd,
    )
    if (
        type(source_freeze) is not dict or type(receipt) is not dict
        or type(policy) is not dict
        or re.fullmatch(r"[0-9a-f]{64}", policy_sha256) is None
        or any(type(fd) is not int or fd < 3 for fd in descriptors)
    ):
        raise BuildError("retained backend generation arguments differ")
    before = tuple(os.fstat(fd) for fd in descriptors)
    module = _load_frozen_source_module(
        "_plamen_frozen_backend_acquisition",
        "native_backend_acquisition", source_freeze,
    )
    binder = getattr(module, "bind_retained_generation_authority", None)
    if not callable(binder):
        raise BuildError("frozen backend acquisition binder is absent")
    try:
        authority = binder(
            receipt=receipt, policy=policy, policy_sha256=policy_sha256,
            verifier=verifier, payload_fd=payload_fd,
            semantic_receipt_fd=semantic_receipt_fd,
            source_manifest_fd=source_manifest_fd,
            verifier_public_key_fd=verifier_public_key_fd,
        )
    except BaseException as exc:
        raise BuildError(
            f"retained backend generation admission failed: {type(exc).__name__}"
        ) from None
    if (
        getattr(authority, "generation", None) is None
        or tuple(getattr(authority, name, None) for name in (
            "payload_fd", "semantic_receipt_fd", "source_manifest_fd",
            "verifier_public_key_fd",
        )) != descriptors
        or any(not _same_stat(expected, os.fstat(fd)) for expected, fd in zip(
            before, descriptors, strict=True,
        ))
    ):
        raise BuildError("retained backend generation custody differs")
    return authority


def _validate_frozen_runtime_source_projection(
    source_freeze: dict[str, Any],
) -> dict[str, Any]:
    """Replay the semantically frozen runtime projection from frozen code.

    A production source freeze may bind the projection bytes only after it has
    bound the validator that interprets them.  Both are read through retained
    no-follow descriptors, and validation is relative to the retained source
    root descriptor rather than a later pathname walk.
    """

    rows = {
        row["role"]: row for row in source_freeze.get("sources", ())
        if type(row) is dict and type(row.get("role")) is str
    }
    manifest_row = rows.get("runtime_source_projection_manifest")
    if manifest_row is None:
        raise BuildError("frozen runtime source projection manifest is unavailable")
    projection = _load_frozen_source_module(
        "_plamen_frozen_runtime_source_projection",
        "runtime_source_projection", source_freeze,
    )
    validator = getattr(projection, "validate_manifest", None)
    if not callable(validator):
        raise BuildError("frozen runtime source projection validator is unavailable")
    source_root_fd = manifest_fd = -1
    try:
        source_root_fd = _open_directory_nofollow(REPOSITORY_ROOT)
        path = REPOSITORY_ROOT / manifest_row["path"]
        manifest_fd, resolved, observed = _open_retained_regular(
            path, "frozen runtime source projection manifest",
        )
        if (
            resolved != path
            or observed["sha256"] != manifest_row["sha256"]
            or observed["size"] != manifest_row["size"]
        ):
            raise BuildError("frozen runtime source projection manifest differs")
        raw = _read_fd(
            manifest_fd, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
            "frozen runtime source projection manifest",
        )
        try:
            validated = validator(
                raw, source_root_fd, require_frozen=True,
                expected_manifest_sha256=manifest_row["sha256"],
            )
        except BaseException as exc:
            raise BuildError(
                "frozen runtime source projection is invalid: "
                + f"{type(exc).__name__}:{exc}"
            ) from None
    finally:
        if manifest_fd >= 0:
            os.close(manifest_fd)
        if source_root_fd >= 0:
            os.close(source_root_fd)
    if (
        type(validated) is not dict
        or validated.get("schema") != "plamen.runtime-source-projection.v1"
        or validated.get("state") != "FROZEN"
        or type(validated.get("rows")) is not list
        or type(validated.get("counts")) is not dict
        or validated["counts"].get("total") != len(validated["rows"])
    ):
        raise BuildError("frozen runtime source projection result differs")
    return {
        "manifest_sha256": manifest_row["sha256"],
        "roster_sha256": validated["roster_sha256"],
        "source_commit": validated["source_commit"],
        "source_count": len(validated["rows"]),
    }


def _open_relative_nofollow(
    root_fd: int, relative: str, *, directory: bool,
) -> int:
    safe = _safe_relative(relative)
    current = os.dup(root_fd)
    try:
        parts = PurePosixPath(safe).parts
        for index, component in enumerate(parts):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            if index < len(parts) - 1 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
        info = os.fstat(current)
        if directory != stat.S_ISDIR(info.st_mode):
            raise BuildError("descriptor-relative source kind differs")
        if not directory and (not stat.S_ISREG(info.st_mode)
                              or info.st_nlink != 1):
            raise BuildError("descriptor-relative source file differs")
        return current
    except BaseException:
        os.close(current)
        raise


def _freeze_materialized_tree(root_fd: int) -> None:
    """Freeze one private projection bottom-up without following entries."""

    before = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o700
    ):
        raise BuildError("materialized projection root is not private")

    def visit(directory_fd: int) -> None:
        names_before = sorted(os.listdir(directory_fd))
        for name in names_before:
            if _SAFE_COMPONENT.fullmatch(name) is None:
                raise BuildError("materialized projection name differs")
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(named.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(child)
                    if not _same_stat(named, opened):
                        raise BuildError("materialized directory changed")
                    visit(child)
                    os.fchmod(child, 0o500); os.fsync(child)
                    if not _same_stat(
                        os.fstat(child), os.stat(
                            name, dir_fd=directory_fd,
                            follow_symlinks=False,
                        ),
                    ):
                        raise BuildError("materialized directory drifted")
                finally:
                    os.close(child)
            elif (
                not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                or named.st_uid != os.geteuid()
                or stat.S_IMODE(named.st_mode) != 0o400
            ):
                raise BuildError("materialized projection file differs")
        if sorted(os.listdir(directory_fd)) != names_before:
            raise BuildError("materialized projection census changed")

    visit(root_fd)
    os.fchmod(root_fd, 0o500); os.fsync(root_fd)


def _open_native_install_layout(home: Path) -> tuple[Path, int, int]:
    """Create/open only the fixed owner-controlled native install controls."""

    install_root = home / ".local" / "share" / "plamen"
    for relative in (
        ".local/share/plamen",
        ".local/share/plamen/generations",
        ".local/share/plamen/bin",
        ".local/share/plamen/share",
        ".local/share/plamen/share/plamen",
        ".local/share/plamen/native-source-stages",
    ):
        descriptor = _open_owned_managed_directory_tree(
            home, PurePosixPath(relative)
        )
        os.close(descriptor)
    return (
        install_root,
        _open_directory_nofollow(install_root),
        _open_directory_nofollow(install_root / "native-source-stages"),
    )


def _normalize_native_runtime_bindings(value: Any) -> dict[str, Any]:
    if (
        type(value) is not dict
        or value.get("schema") != "plamen.native-runtime-bindings.v2"
        or type(value.get("references")) is not dict
        or type(value.get("digests")) is not dict
    ):
        raise BuildError("native runtime bindings authority is malformed")
    references = value["references"]
    digests = value["digests"]
    bindings = {
        "target_arch": "arm64",
        "oci_image_reference": references.get("oci_image_reference"),
        "oci_init_reference": references.get("oci_init_reference"),
        **{field: digests.get(field) for field in (
            RUNTIME_PACKAGE_MANIFEST_V2_DIGEST_FIELDS
        )},
    }
    _runtime_manifest_binding(bindings)
    return bindings


def _frozen_source_row(
    source_freeze: dict[str, Any], role: str,
) -> dict[str, Any]:
    rows = [
        row for row in source_freeze.get("sources", ())
        if type(row) is dict and row.get("role") == role
    ]
    if len(rows) != 1:
        raise BuildError(f"frozen source role {role} is unavailable")
    return dict(rows[0])


def _read_frozen_source_member(
    source_freeze: dict[str, Any], role: str,
) -> bytes:
    row = _frozen_source_row(source_freeze, role)
    descriptor = -1
    try:
        path = REPOSITORY_ROOT / row["path"]
        descriptor, resolved, observed = _open_retained_regular(
            path, f"frozen source {role}",
        )
        if (
            resolved != path
            or observed["size"] != row["size"]
            or observed["sha256"] != row["sha256"]
        ):
            raise BuildError(f"frozen source {role} differs")
        return _read_fd(
            descriptor, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
            f"frozen source {role}",
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _snapshot_file_authority(source: Path, destination: Path) -> dict[str, Any]:
    descriptor = -1
    try:
        descriptor, resolved, identity = _open_retained_regular(
            source, "package snapshot member",
        )
        if resolved != source:
            raise BuildError("package snapshot member is aliased")
        return {
            "schema": "plamen.posix-native-install.file-authority.v1",
            "path": str(destination),
            "device": identity["device"], "inode": identity["inode"],
            "mode": identity["mode"], "size": identity["size"],
            "sha256": identity["sha256"],
        }
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _snapshot_runtime_command(argv: list[str], *, pass_fds: tuple[int, ...] = ()) -> bytes:
    """Run one bounded managed-runtime build/probe command in the closed env."""

    try:
        completed = subprocess.run(
            argv, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=_CLOSED_ENV, timeout=1800, pass_fds=pass_fds,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("managed runtime materialization command failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > MAX_COMPILER_OUTPUT_BYTES:
        raise BuildError(
            "managed runtime materialization command failed: "
            + completed.stdout.decode("utf-8", "replace")[:4096]
        )
    return completed.stdout


def _record_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    digest = digest.digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _stream_contains(path: Path, needle: bytes) -> bool:
    """Search an ordinary file without ever materializing a large wheel leaf."""

    if not needle:
        raise BuildError("managed runtime relocation needle is empty")
    overlap = b""
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return False
            candidate = overlap + block
            if needle in candidate:
                return True
            overlap = candidate[-(len(needle) - 1):] if len(needle) > 1 else b""


def _relocate_managed_runtime_text(staged: Path, final: Path) -> None:
    """Rewrite bounded venv text, then stream-prove no private prefix remains."""

    old = os.fspath(staged).encode("utf-8")
    new = os.fspath(final).encode("utf-8")
    changed: set[Path] = set()
    records: list[Path] = []
    for path in sorted(staged.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise BuildError("managed runtime contains a symbolic link")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise BuildError("managed runtime contains a linked or special member")
        if path.name == "RECORD" and path.parent.name.endswith(".dist-info"):
            records.append(path)
            continue
        # CPython venv embeds its creation prefix only in pyvenv.cfg and
        # generated bin/ scripts.  Do not load or rewrite arbitrary wheel
        # binaries: some production leaves are hundreds of MiB.  Any
        # unexpected embedded prefix is rejected by the streaming census
        # below instead of being silently modified.
        relative = path.relative_to(staged)
        rewrite_candidate = (
            relative == Path("pyvenv.cfg")
            or relative.parts[:1] == ("bin",)
        )
        if rewrite_candidate and _stream_contains(path, old):
            if info.st_size > 16 * 1024 * 1024:
                raise BuildError("managed runtime relocation text is oversized")
            raw = path.read_bytes()
            path.write_bytes(raw.replace(old, new))
            changed.add(path.resolve(strict=True))
    for record in records:
        site_root = record.parent.parent
        with record.open("r", encoding="utf-8", newline="") as stream:
            rows = list(csv.reader(stream))
        touched = False
        for row in rows:
            if len(row) != 3:
                raise BuildError("managed runtime RECORD is malformed")
            try:
                candidate = (site_root / row[0]).resolve(strict=True)
            except (FileNotFoundError, RuntimeError):
                continue
            if candidate in changed:
                row[1] = _record_hash(candidate)
                row[2] = str(candidate.stat().st_size)
                touched = True
        if touched:
            with record.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream, lineterminator="\n")
                writer.writerows(rows)
    for path in sorted(staged.rglob("*")):
        if path.is_file() and _stream_contains(path, old):
            raise BuildError("managed runtime retains its private staging prefix")


def _normalize_managed_pyvenv_config(
    root: Path, retained_interpreter: dict[str, Any],
) -> None:
    """Remove ephemeral /dev/fd provenance from the host-local venv."""

    resolved = retained_interpreter.get("path")
    version = retained_interpreter.get("python_version")
    if (
        not isinstance(resolved, Path) or not resolved.is_absolute()
        or type(version) is not list or len(version) != 3
        or any(type(part) is not int or part < 0 for part in version)
    ):
        raise BuildError("retained CPython authority is malformed")
    config = root / "pyvenv.cfg"
    before = config.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise BuildError("managed runtime pyvenv.cfg authority differs")
    payload = (
        f"home = {resolved.parent}\n"
        "include-system-site-packages = false\n"
        f"version = {'.'.join(str(part) for part in version)}\n"
        f"executable = {resolved}\n"
    ).encode("utf-8")
    if b"/dev/fd/" in payload:
        raise BuildError("managed runtime base interpreter is ephemeral")
    config.write_bytes(payload)


def _managed_runtime_census(root: Path) -> list[dict[str, Any]]:
    """Return the exact ordinary-file census, rejecting all physical aliases."""

    rows: list[dict[str, Any]] = []
    total = 0
    identities: set[tuple[int, int]] = set()
    directories: set[tuple[int, int]] = set()
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directory_info = os.lstat(directory_path)
        directory_identity = (directory_info.st_dev, directory_info.st_ino)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or stat.S_ISLNK(directory_info.st_mode)
            or directory_identity in directories
        ):
            raise BuildError("managed runtime directory authority differs")
        directories.add(directory_identity)
        for name in sorted(names):
            info = os.lstat(directory_path / name)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise BuildError("managed runtime contains a directory alias")
        for name in sorted(filenames):
            path = directory_path / name
            descriptor = -1
            try:
                before = os.lstat(path)
                descriptor = os.open(
                    path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                info = os.fstat(descriptor)
                physical = (info.st_dev, info.st_ino)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or not _same_stat(before, info)
                    or info.st_nlink != 1 or physical in identities
                ):
                    raise BuildError("managed runtime contains a physical alias")
                identities.add(physical)
                size = info.st_size
                total += size
                if (
                    size > PRODUCTION_PACKAGE_SNAPSHOT_MAX_MEMBER_BYTES
                    or total > PRODUCTION_PACKAGE_SNAPSHOT_MAX_BYTES
                    or len(rows) >= PRODUCTION_PACKAGE_SNAPSHOT_MAX_ROWS
                ):
                    raise BuildError("managed runtime exceeds its frozen bounds")
                relative = path.relative_to(root).as_posix()
                mode = 0o500 if stat.S_IMODE(info.st_mode) & 0o100 else 0o400
                os.fchmod(descriptor, mode); os.fsync(descriptor)
                final = os.fstat(descriptor)
                rows.append({
                    "namespace": "managed-runtime", "path": relative,
                    "mode": mode, "size": final.st_size,
                    "sha256": _sha256_fd(descriptor, final.st_size),
                })
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    return rows


def _prune_empty_snapshot_directories(root: Path) -> None:
    for path in sorted(
        (item for item in root.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts), reverse=True,
    ):
        try:
            path.rmdir()
        except OSError:
            pass


def _freeze_snapshot_directories(root: Path) -> None:
    directories = [root]
    for directory, names, _files in os.walk(root, followlinks=False):
        parent = Path(directory)
        for name in sorted(names):
            child = parent / name
            info = os.lstat(child)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise BuildError("package snapshot contains a directory alias")
            directories.append(child)
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        descriptor = _open_directory_nofollow(directory)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid():
                raise BuildError("package snapshot directory owner differs")
            os.fchmod(descriptor, 0o500); os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _materialize_relocatable_managed_runtime(
    root: Path, final_root: Path, package_source_root: Path,
) -> list[dict[str, Any]]:
    """Build the complete hash-locked CPython venv for atomic publication."""

    if root.exists() or root.is_symlink():
        raise BuildError("managed runtime snapshot destination already exists")
    retained = _retain_production_cpython_312()
    descriptor = retained["fd"]
    try:
        executable = f"/dev/fd/{descriptor}"
        _snapshot_runtime_command(
            [executable, "-I", "-B", "-m", "venv", "--copies", os.fspath(root)],
            pass_fds=(descriptor,),
        )
        _normalize_managed_pyvenv_config(root, retained)
        # A descriptor-backed creation command must not remain a hidden
        # runtime dependency.  Close it before pip and every executable probe.
        os.close(descriptor); descriptor = -1
        python = root / "bin" / "python"
        lock = package_source_root / "requirements-runtime-full.lock"
        core_lock = package_source_root / "requirements-runtime-core.lock"
        if not lock.is_file() or lock.is_symlink() or not core_lock.is_file() or core_lock.is_symlink():
            raise BuildError("frozen managed runtime lock is unavailable")
        _snapshot_runtime_command([
            os.fspath(python), "-I", "-B", "-m", "pip", "install",
            "--isolated", "--disable-pip-version-check", "--no-input",
            "--no-cache-dir", "--require-hashes", "--only-binary=:all:",
            "--force-reinstall", "-r", os.fspath(lock),
        ])
        stamp = {
            "lock_sha256": hashlib.sha256(core_lock.read_bytes()).hexdigest(),
            "python_abi": "cp312", "schema": "plamen.python_runtime.v1",
        }
        stamp_path = root / ".plamen-runtime.json"
        stamp_path.write_bytes(_canonical_json_bytes(stamp))
        _relocate_managed_runtime_text(root, final_root)
        for path in sorted(root.rglob("*")):
            if path.is_file() and _stream_contains(path, b"/dev/fd/"):
                raise BuildError("managed runtime retains ephemeral fd provenance")
        probe = json.loads(_snapshot_runtime_command([
            os.fspath(python), "-I", "-B", "-c",
            "import json,sys; import InquirerPy,chromadb,jsonschema,mcp,pydantic,rich,sentence_transformers; "
            "print(json.dumps({'prefix':sys.prefix,'version':list(sys.version_info[:2])}))",
        ]))
        if probe != {"prefix": os.fspath(root), "version": [3, 12]}:
            raise BuildError("staged managed runtime interpreter identity differs")
        _snapshot_runtime_command([
            os.fspath(python), "-I", "-B", "-m", "pip", "check",
        ])
        _prune_empty_snapshot_directories(root)
        preliminary = _managed_runtime_census(root)
        census = {
            "schema": "plamen.posix-native-install.managed-runtime-census.v1",
            "final_root": os.fspath(final_root),
            "full_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "row_count": len(preliminary),
            "total_bytes": sum(row["size"] for row in preliminary),
            "rows_sha256": hashlib.sha256(
                _canonical_json_bytes(preliminary)
            ).hexdigest(),
        }
        census_path = root / ".plamen-native-install-census.json"
        census_path.write_bytes(_canonical_json_bytes(census))
        rows = _managed_runtime_census(root)
        _freeze_snapshot_directories(root)
        return rows
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _materialize_frozen_package_snapshot(
    workspace: Path, home: Path, source_freeze: dict[str, Any],
) -> dict[str, Any]:
    """Create the exact private package denominator consumed by cold install.

    Repository paths never become install authority.  The frozen projection
    validator copies the exact legacy package source layout and a complete,
    relocatable, hash-locked CPython venv is constructed beside it.  The
    effects adapter durably restages and replays every resulting row.
    """

    workspace = _canonical_absolute_path(workspace, "package snapshot workspace")
    home = _canonical_absolute_path(home, "package snapshot account home")
    workspace_fd = source_root_fd = snapshot_fd = runtime_fd = adapter_fd = -1
    try:
        workspace_fd = _open_directory_nofollow(workspace)
        workspace_info = os.fstat(workspace_fd)
        if (
            workspace_info.st_uid != os.geteuid()
            or stat.S_IMODE(workspace_info.st_mode) != 0o700
            or os.listdir(workspace_fd)
        ):
            raise BuildError("package snapshot workspace is not empty and private")
        snapshot_fd = _mkdir_new(workspace_fd, "package-snapshot")
        runtime_fd = _mkdir_new(snapshot_fd, "package-source")
        adapter_fd = _mkdir_new(runtime_fd, "codex-adapter")
        source_root_fd = _open_directory_nofollow(REPOSITORY_ROOT)
        projection = _load_frozen_source_module(
            "_plamen_frozen_runtime_source_projection_materializer",
            "runtime_source_projection", source_freeze,
        )
        manifest_raw = _read_frozen_source_member(
            source_freeze, "runtime_source_projection_manifest",
        )
        manifest_row = _frozen_source_row(
            source_freeze, "runtime_source_projection_manifest",
        )
        validate = getattr(projection, "validate_manifest", None)
        materialize = getattr(projection, "materialize_validated", None)
        if not callable(validate) or not callable(materialize):
            raise BuildError("frozen runtime projection materializer is unavailable")
        projection_authority = validate(
            manifest_raw, source_root_fd, require_frozen=True,
            expected_manifest_sha256=manifest_row["sha256"],
        )
        materialized = materialize(
            manifest_raw, source_root_fd, runtime_fd, adapter_fd,
            expected_manifest_sha256=manifest_row["sha256"],
        )
        if materialized.get("count") != projection_authority["counts"]["total"]:
            raise BuildError("package projection materialization denominator differs")

        rows: list[dict[str, Any]] = []
        for row in projection_authority["rows"]:
            relative = (
                row["destination_path"] if row["class"] == "runtime"
                else f"codex-adapter/{row['destination_path']}"
            )
            staged = workspace / "package-snapshot/package-source" / relative
            descriptor = -1
            try:
                descriptor, resolved, observed = _open_retained_regular(
                    staged, "materialized package member",
                )
                if (
                    resolved != staged or observed["mode"] != row["installed_mode"]
                    or observed["size"] != row["size"]
                    or observed["sha256"] != row["sha256"]
                ):
                    raise BuildError("materialized package member differs")
                rows.append({
                    "namespace": "package-source", "path": relative,
                    "mode": observed["mode"],
                    "size": observed["size"], "sha256": observed["sha256"],
                })
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        managed_root = workspace / "package-snapshot/managed-runtime"
        final_runtime = home / ".local/share/plamen/runtime/py312"
        rows.extend(_materialize_relocatable_managed_runtime(
            managed_root, final_runtime,
            workspace / "package-snapshot/package-source",
        ))
        rows.sort(key=lambda row: (
            row["namespace"].encode("utf-8"), row["path"].encode("utf-8"),
        ))
        if (
            len(rows) > PRODUCTION_PACKAGE_SNAPSHOT_MAX_ROWS
            or sum(row["size"] for row in rows)
            > PRODUCTION_PACKAGE_SNAPSHOT_MAX_BYTES
        ):
            raise BuildError("package snapshot exceeds its frozen bounds")
        _freeze_snapshot_directories(
            workspace / "package-snapshot/package-source",
        )
        front_source = workspace / "package-snapshot/package-source/plamen.py"
        python_source = workspace / "package-snapshot/managed-runtime/bin/python"
        manifest = {
            "schema": "plamen.posix-native-install.package-snapshot.v2",
            "rows": rows,
        }
        return {
            **manifest,
            "root": str(workspace / "package-snapshot"),
            "manifest_sha256": hashlib.sha256(
                _canonical_json_bytes(manifest)
            ).hexdigest(),
            "interpreter_authority": _snapshot_file_authority(
                python_source,
                home / ".local/share/plamen/runtime/py312/bin/python",
            ),
            "front_authority": _snapshot_file_authority(
                front_source, home / ".plamen/plamen.py",
            ),
        }
    finally:
        for descriptor in (
            adapter_fd, runtime_fd, snapshot_fd, source_root_fd, workspace_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)


def _retain_production_cpython_312() -> dict[str, Any]:
    """Retain and bind the host-local interpreter used as generation member 6.

    The portable source freeze binds the CPython 3.12 policy and this verifier,
    never a machine-specific Homebrew/Python.org pathname or inode.  The exact
    executable identity and Darwin code identity are instead captured here and
    consumed by the per-install native receipt while the descriptor remains
    open.  The caller owns and must close the returned descriptor.
    """

    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:2] != PRODUCTION_CPYTHON_ABI
        or sys.platform != "darwin"
        or os.uname().machine != "arm64"
    ):
        raise BuildError("production interpreter is not CPython 3.12 Darwin arm64")
    descriptor = -1
    try:
        descriptor, resolved, identity = _open_retained_regular(
            Path(sys.executable), "production CPython 3.12 executable",
        )
        info = os.fstat(descriptor)
        if (
            info.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(info.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or not stat.S_IMODE(info.st_mode) & stat.S_IXUSR
        ):
            raise BuildError("production CPython executable authority differs")
        code_identity = _darwin_ad_hoc_code_identity(
            resolved, "production CPython 3.12 executable",
            retained_fd=descriptor,
        )
        if not code_identity["identifier"]:
            raise BuildError("production CPython code identifier is absent")
        # A final descriptor replay closes substitution between code-signature
        # observation and handoff to the native receipt encoder.
        current = os.fstat(descriptor)
        if (
            not _same_stat(info, current)
            or _sha256_fd(descriptor, current.st_size) != identity["sha256"]
        ):
            raise BuildError("production CPython changed before retained handoff")
        return {
            "fd": descriptor,
            "path": resolved,
            "identity": identity,
            "code_identity": code_identity,
            "python_version": [
                sys.version_info.major, sys.version_info.minor,
                sys.version_info.micro,
            ],
        }
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


class _RetainedFrozenSourceRoster:
    """Descriptor-bound source denominator for setup-time materializers.

    The cold-install coordinator's serialized source observation is useful for
    journal replay, but it is not descriptor custody.  This object retains
    every source-freeze member and permits consumers to duplicate only an
    already-replayed vnode.  It deliberately exposes no root pathname or API
    that can reopen a member later.
    """

    __slots__ = ("_rows", "_fds", "_projections", "_closed")
    _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True
    _PLAMEN_RETAINED_FIXED_ROLE_SOURCE_V1 = True

    def __init__(
        self, rows: dict[str, MappingProxyType], descriptors: dict[str, int],
    ) -> None:
        self._rows = MappingProxyType(dict(rows))
        self._fds = dict(descriptors)
        self._projections: dict[str, tuple[int, tuple[int, ...]]] = {}
        self._closed = False

    def roles(self) -> tuple[str, ...]:
        if self._closed:
            raise BuildError("retained frozen source roster is closed")
        return tuple(sorted(self._rows, key=lambda value: value.encode("utf-8")))

    def duplicate(self, role: str) -> tuple[MappingProxyType, int]:
        if self._closed or type(role) is not str or role not in self._rows:
            raise BuildError("retained frozen source role is unavailable")
        source_fd = self._fds[role]
        row = self._rows[role]
        try:
            before = os.fstat(source_fd)
            if (
                not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size != row["size"]
                or _sha256_fd(source_fd, before.st_size) != row["sha256"]
            ):
                raise BuildError("retained frozen source member drifted")
            duplicate = os.dup(source_fd)
            os.set_inheritable(duplicate, False)
            if not _same_stat(before, os.fstat(duplicate)):
                os.close(duplicate)
                raise BuildError("retained frozen source duplicate differs")
            return row, duplicate
        except BuildError:
            raise
        except OSError as exc:
            raise BuildError(
                "retained frozen source member is unavailable"
            ) from exc

    def duplicate_member(self, role: str) -> int:
        """Return only a new retained member FD for a frozen consumer."""

        _row, descriptor = self.duplicate(role)
        return descriptor

    @staticmethod
    def _projection_fd(fd: int, label: str) -> os.stat_result:
        if type(fd) is not int or fd < 3 or fcntl is None:
            raise BuildError(f"retained {label} descriptor differs")
        try:
            info = os.fstat(fd)
            status = fcntl.fcntl(fd, fcntl.F_GETFL)
            descriptor = fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError as exc:
            raise BuildError(
                f"retained {label} descriptor is unavailable"
            ) from exc
        if (
            status & os.O_ACCMODE != os.O_RDONLY
            or not descriptor & fcntl.FD_CLOEXEC
            or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(info.st_mode) & 0o022
            or not 0 < info.st_size <= 2 * 1024 * 1024 * 1024
        ):
            raise BuildError(f"retained {label} authority differs")
        return info

    def seal_projection(
        self, role: str, manifest_fd: int, member_fds: tuple[int, ...],
    ) -> bool:
        """Attach one complete descriptor-only projection before consumption.

        Compilation and source projection happen before fixed-role material
        acquisition.  This one-way seal lets that preparer attach the resulting
        vnodes without a callback, pathname, or serialized content handoff.
        """

        if (
            self._closed or role not in {"plamen_guest", "plamen_package"}
            or role in self._projections or type(member_fds) is not tuple
            or not member_fds
        ):
            raise BuildError("retained source projection seal differs")
        self._projection_fd(manifest_fd, f"{role} projection manifest")
        raw = _read_fd(
            manifest_fd, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
            f"{role} projection manifest",
        )
        try:
            value = json.loads(raw.decode("ascii"))
        except (UnicodeError, ValueError):
            raise BuildError("retained source projection manifest is malformed") from None
        canonical = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        rows = value.get("rows") if type(value) is dict else None
        authority = value.get("projection_authority") if type(value) is dict else None
        if (
            canonical != raw
            or type(value) is not dict
            or set(value) != {
                "projection_authority", "role", "roster_sha256", "rows",
                "schema", "source_commit",
            }
            or value.get("schema") != "plamen.fixed-role-source-projection.v1"
            or value.get("role") != role
            or re.fullmatch(r"[0-9a-f]{40}", value.get("source_commit", ""))
            is None
            or re.fullmatch(r"[0-9a-f]{64}", value.get("roster_sha256", ""))
            is None
            or type(authority) is not dict
            or set(authority) != {"schema", "sha256", "size"}
            or type(authority.get("schema")) is not str
            or not authority["schema"].startswith(
                "plamen.native-" if role == "plamen_guest"
                else "plamen.runtime-source-projection."
            )
            or re.fullmatch(r"[0-9a-f]{64}", authority.get("sha256", ""))
            is None
            or type(authority.get("size")) is not int
            or not 0 < authority["size"] <= PRODUCTION_SOURCE_MEMBER_MAX_BYTES
            or type(rows) is not list or len(rows) != len(member_fds)
            or not rows
        ):
            raise BuildError("retained source projection manifest differs")
        roster = hashlib.sha256(b"PLAMEN-FIXED-ROLE-SOURCE-PROJECTION-V1\0")
        identities: set[tuple[int, int]] = set()
        prior: bytes | None = None
        for row, member_fd in zip(rows, member_fds, strict=True):
            info = self._projection_fd(member_fd, f"{role} projection member")
            if (
                type(row) is not dict
                or set(row) != {"mode", "path", "sha256", "size"}
                or type(row.get("path")) is not str
                or _safe_relative(row.get("path")) != row["path"]
                or type(row.get("mode")) is not int
                or row["mode"] not in {0o400, 0o500}
                or type(row.get("size")) is not int
                or row["size"] != info.st_size
                or re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) is None
                or _sha256_fd(member_fd, info.st_size) != row["sha256"]
            ):
                raise BuildError("retained source projection member differs")
            encoded = row["path"].encode("utf-8")
            identity = (int(info.st_dev), int(info.st_ino))
            if (prior is not None and encoded <= prior) or identity in identities:
                raise BuildError("retained source projection roster differs")
            prior = encoded
            identities.add(identity)
            roster.update(len(encoded).to_bytes(4, "big")); roster.update(encoded)
            roster.update(row["mode"].to_bytes(4, "big"))
            roster.update(row["size"].to_bytes(8, "big"))
            roster.update(bytes.fromhex(row["sha256"]))
        if roster.hexdigest() != value["roster_sha256"]:
            raise BuildError("retained source projection roster digest differs")
        duplicates: list[int] = []
        try:
            duplicates = [os.dup(manifest_fd), *(os.dup(fd) for fd in member_fds)]
            for descriptor in duplicates:
                os.set_inheritable(descriptor, False)
            self._projections[role] = (duplicates[0], tuple(duplicates[1:]))
        except BaseException:
            for descriptor in duplicates:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        return True

    def duplicate_projection_manifest(self, role: str) -> int:
        if self._closed or role not in self._projections:
            raise BuildError("retained source projection is unavailable")
        descriptor = os.dup(self._projections[role][0])
        os.set_inheritable(descriptor, False)
        return descriptor

    def duplicate_projection_member(self, role: str, index: int) -> int:
        if (
            self._closed or role not in self._projections
            or type(index) is not int
            or not 0 <= index < len(self._projections[role][1])
        ):
            raise BuildError("retained source projection member is unavailable")
        descriptor = os.dup(self._projections[role][1][index])
        os.set_inheritable(descriptor, False)
        return descriptor

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        descriptors, self._fds = self._fds, {}
        projections, self._projections = self._projections, {}
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        for manifest, members in projections.values():
            for descriptor in (manifest, *members):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        return True


def _retain_exact_frozen_source_roster(
    source_freeze: dict[str, Any],
) -> _RetainedFrozenSourceRoster:
    """Replay and retain every frozen source file without path handoff."""

    if (
        type(source_freeze) is not dict
        or source_freeze.get("schema") != PRODUCTION_SOURCE_FREEZE_SCHEMA
        or type(source_freeze.get("sources")) is not list
        or not source_freeze["sources"]
    ):
        raise BuildError("production frozen source roster is malformed")
    expected_roles = {role for role, _path in PRODUCTION_DARWIN_SOURCE_ROSTER}
    rows: dict[str, MappingProxyType] = {}
    descriptors: dict[str, int] = {}
    root_fd = -1
    try:
        root_fd = _open_directory_nofollow(REPOSITORY_ROOT)
        for item in source_freeze["sources"]:
            if (
                type(item) is not dict
                or set(item) != {"path", "role", "sha256", "size"}
                or type(item.get("role")) is not str
                or item["role"] in rows
                or type(item.get("size")) is not int
                or not 1 <= item["size"] <= PRODUCTION_SOURCE_MEMBER_MAX_BYTES
                or re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
                is None
            ):
                raise BuildError("production frozen source row differs")
            relative = _safe_relative(item.get("path"))
            descriptor = _open_relative_nofollow(
                root_fd, relative, directory=False,
            )
            info = os.fstat(descriptor)
            if (
                info.st_size != item["size"]
                or _sha256_fd(descriptor, info.st_size) != item["sha256"]
            ):
                os.close(descriptor)
                raise BuildError(
                    f"frozen source {item['role']} differs at retained handoff"
                )
            rows[item["role"]] = MappingProxyType(dict(item))
            descriptors[item["role"]] = descriptor
        if set(rows) != expected_roles:
            raise BuildError("production frozen source denominator differs")
        return _RetainedFrozenSourceRoster(rows, descriptors)
    except BaseException:
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    finally:
        if root_fd >= 0:
            os.close(root_fd)


def _fixed_role_projection_manifest(
    *, role: str, source_commit: str, authority: dict[str, Any],
    rows: list[dict[str, Any]],
) -> bytes:
    if (
        role not in {"plamen_guest", "plamen_package"}
        or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
        or type(authority) is not dict
        or set(authority) != {"schema", "sha256", "size"}
        or type(authority.get("schema")) is not str
        or not authority["schema"].startswith(
            "plamen.native-" if role == "plamen_guest"
            else "plamen.runtime-source-projection."
        )
        or re.fullmatch(r"[0-9a-f]{64}", authority.get("sha256", "")) is None
        or type(authority.get("size")) is not int
        or authority["size"] <= 0
        or type(rows) is not list or not rows
    ):
        raise BuildError("fixed-role source projection authority differs")
    normalized: list[dict[str, Any]] = []
    prior: bytes | None = None
    roster = hashlib.sha256(b"PLAMEN-FIXED-ROLE-SOURCE-PROJECTION-V1\0")
    for row in rows:
        if (
            type(row) is not dict
            or set(row) != {"mode", "path", "sha256", "size"}
            or type(row.get("path")) is not str
            or _safe_relative(row["path"]) != row["path"]
            or row.get("mode") not in {0o400, 0o500}
            or type(row.get("size")) is not int or row["size"] <= 0
            or re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) is None
        ):
            raise BuildError("fixed-role source projection row differs")
        encoded = row["path"].encode("utf-8")
        if prior is not None and encoded <= prior:
            raise BuildError("fixed-role source projection order differs")
        prior = encoded
        normalized.append(dict(row))
        roster.update(len(encoded).to_bytes(4, "big")); roster.update(encoded)
        roster.update(row["mode"].to_bytes(4, "big"))
        roster.update(row["size"].to_bytes(8, "big"))
        roster.update(bytes.fromhex(row["sha256"]))
    return json.dumps({
        "projection_authority": dict(authority), "role": role,
        "roster_sha256": roster.hexdigest(), "rows": normalized,
        "schema": "plamen.fixed-role-source-projection.v1",
        "source_commit": source_commit,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
       allow_nan=False).encode("ascii")


def _write_and_seal_fixed_role_projection(
    *, source_roster: _RetainedFrozenSourceRoster, private_store: Any,
    role: str, manifest_raw: bytes, member_fds: tuple[int, ...],
) -> MappingProxyType:
    pair = getattr(private_store, "pair", None)
    if not callable(pair):
        raise BuildError("fixed-role projection private store differs")
    writer = reader = -1
    try:
        writer, reader = pair(f"{role}-source-projection", linked=True)
        if (
            type(writer) is not int or writer < 3
            or type(reader) is not int or reader < 3 or writer == reader
        ):
            raise BuildError("fixed-role projection output pair differs")
        _write_all(writer, manifest_raw); os.fsync(writer); os.fchmod(writer, 0o400)
        info = os.fstat(reader)
        if (
            info.st_size != len(manifest_raw)
            or _sha256_fd(reader, info.st_size)
            != hashlib.sha256(manifest_raw).hexdigest()
        ):
            raise BuildError("fixed-role projection manifest write differs")
        if source_roster.seal_projection(role, reader, member_fds) is not True:
            raise BuildError("fixed-role projection seal was rejected")
        decoded = json.loads(manifest_raw.decode("ascii"))
        return MappingProxyType({
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "manifest_size": len(manifest_raw),
            "projection_authority_sha256": decoded["projection_authority"][
                "sha256"
            ],
            "roster_sha256": decoded["roster_sha256"],
        })
    finally:
        for descriptor in (writer, reader):
            if descriptor >= 0:
                os.close(descriptor)


def _seal_production_fixed_role_source_projections(
    *, source_freeze: dict[str, Any],
    source_roster: _RetainedFrozenSourceRoster,
    package_snapshot: dict[str, Any],
    compiled_artifacts: dict[str, dict[str, Any]], private_store: Any,
) -> MappingProxyType:
    """Seal exact role-2/4 members without embedding operation-4 policy.

    Role 2 binds only the already-signed extension and fixed guest bootstrap.
    Its independently derived authority names the future host install receipt
    as an external authority, so neither the generated operation-4 policy nor
    its standalone coordinator enters the guest payload hash.  Role 4 is the
    exact package-source projection already authenticated by the frozen
    runtime-source manifest.
    """

    if (
        type(source_freeze) is not dict
        or type(package_snapshot) is not dict
        or type(compiled_artifacts) is not dict
        or getattr(
            source_roster, "_PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1", None,
        ) is not True
    ):
        raise BuildError("fixed-role projection inputs differ")
    freeze_sha256 = source_freeze.get("manifest_sha256", "")
    if re.fullmatch(r"[0-9a-f]{64}", freeze_sha256) is None:
        raise BuildError("fixed-role projection source freeze differs")
    manifest_row = next((
        row for row in source_freeze.get("sources", ())
        if type(row) is dict
        and row.get("role") == "runtime_source_projection_manifest"
    ), None)
    runtime_manifest_fd = bootstrap_fd = package_root_fd = -1
    package_fds: list[int] = []
    try:
        runtime_manifest_fd = source_roster.duplicate_member(
            "runtime_source_projection_manifest"
        )
        runtime_raw = _read_fd(
            runtime_manifest_fd, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
            "fixed-role runtime projection authority",
        )
        try:
            runtime_value = json.loads(runtime_raw.decode("ascii"))
        except (UnicodeError, ValueError):
            raise BuildError("fixed-role runtime projection is malformed") from None
        source_commit = (
            runtime_value.get("source_commit")
            if type(runtime_value) is dict else None
        )
        if (
            type(manifest_row) is not dict
            or manifest_row.get("size") != len(runtime_raw)
            or manifest_row.get("sha256")
            != hashlib.sha256(runtime_raw).hexdigest()
            or runtime_value.get("schema")
            != "plamen.runtime-source-projection.v1"
            or runtime_value.get("state") != "FROZEN"
            or re.fullmatch(r"[0-9a-f]{40}", source_commit or "") is None
        ):
            raise BuildError("fixed-role runtime projection authority differs")

        extension = compiled_artifacts.get("cpython-extension")
        extension_fd = extension.get("fd", -1) if type(extension) is dict else -1
        extension_identity = (
            extension.get("identity") if type(extension) is dict else None
        )
        if (
            type(extension_identity) is not dict
            or type(extension_fd) is not int or extension_fd < 3
            or extension.get("artifact")
            != "_plamen_native_supervisor.cpython-312-darwin.so"
        ):
            raise BuildError("fixed-role guest extension authority differs")
        extension_info = os.fstat(extension_fd)
        if (
            extension_info.st_size != extension_identity.get("size")
            or _sha256_fd(extension_fd, extension_info.st_size)
            != extension_identity.get("sha256")
        ):
            raise BuildError("fixed-role guest extension changed")
        bootstrap_fd = source_roster.duplicate_member("posix_guest_bootstrap")
        bootstrap_info = os.fstat(bootstrap_fd)
        bootstrap_sha256 = _sha256_fd(bootstrap_fd, bootstrap_info.st_size)
        guest_rows = sorted([
            {
                "mode": 0o400,
                "path": "lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
                "sha256": extension_identity["sha256"],
                "size": extension_identity["size"],
            },
            {
                "mode": 0o500, "path": "libexec/plamen-guest",
                "sha256": bootstrap_sha256, "size": bootstrap_info.st_size,
            },
        ], key=lambda row: row["path"].encode("utf-8"))
        guest_members = tuple(
            extension_fd if row["path"].startswith("lib/plamen/")
            else bootstrap_fd for row in guest_rows
        )
        guest_authority_raw = json.dumps({
            "external_authority": "HOST_NATIVE_INSTALL_RECEIPT_V2",
            "operation4_policy_location": "STANDALONE_COORDINATOR_ONLY",
            "rows": guest_rows,
            "schema": "plamen.native-guest-source-projection.v1",
            "source_commit": source_commit,
            "source_freeze_sha256": freeze_sha256,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
           allow_nan=False).encode("ascii")
        guest_manifest = _fixed_role_projection_manifest(
            role="plamen_guest", source_commit=source_commit,
            authority={
                "schema": "plamen.native-guest-source-projection.v1",
                "sha256": hashlib.sha256(guest_authority_raw).hexdigest(),
                "size": len(guest_authority_raw),
            }, rows=guest_rows,
        )
        guest_result = _write_and_seal_fixed_role_projection(
            source_roster=source_roster, private_store=private_store,
            role="plamen_guest", manifest_raw=guest_manifest,
            member_fds=guest_members,
        )

        snapshot_rows = package_snapshot.get("rows")
        snapshot_manifest = {
            "schema": package_snapshot.get("schema"), "rows": snapshot_rows,
        }
        if (
            package_snapshot.get("schema")
            != "plamen.posix-native-install.package-snapshot.v2"
            or type(snapshot_rows) is not list or not snapshot_rows
            or package_snapshot.get("manifest_sha256")
            != hashlib.sha256(_canonical_json_bytes(snapshot_manifest)).hexdigest()
            or type(package_snapshot.get("root")) is not str
            or not Path(package_snapshot["root"]).is_absolute()
        ):
            raise BuildError("fixed-role package snapshot authority differs")
        package_rows = [
            row for row in snapshot_rows
            if type(row) is dict and row.get("namespace") == "package-source"
        ]
        if not package_rows:
            raise BuildError("fixed-role package source projection is empty")
        package_root_fd = _open_directory_nofollow(
            Path(package_snapshot["root"]) / "package-source"
        )
        package_root_info = os.fstat(package_root_fd)
        if (
            package_root_info.st_uid != os.geteuid()
            or stat.S_IMODE(package_root_info.st_mode) != 0o500
        ):
            raise BuildError("fixed-role package source root is not private")
        projection_rows: list[dict[str, Any]] = []
        for row in package_rows:
            if (
                set(row) != {"namespace", "path", "mode", "size", "sha256"}
                or row.get("mode") not in {0o400, 0o500}
                or type(row.get("size")) is not int or row["size"] <= 0
                or re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) is None
            ):
                raise BuildError("fixed-role package source row differs")
            descriptor = _open_relative_nofollow(
                package_root_fd, row["path"], directory=False,
            )
            package_fds.append(descriptor)
            info = os.fstat(descriptor)
            if (
                info.st_size != row["size"]
                or _sha256_fd(descriptor, info.st_size) != row["sha256"]
            ):
                raise BuildError("fixed-role package source member differs")
            projection_rows.append({
                "mode": row["mode"], "path": row["path"],
                "sha256": row["sha256"], "size": row["size"],
            })
        ordered = sorted(
            zip(projection_rows, package_fds, strict=True),
            key=lambda item: item[0]["path"].encode("utf-8"),
        )
        projection_rows = [row for row, _descriptor in ordered]
        ordered_fds = tuple(descriptor for _row, descriptor in ordered)
        package_manifest = _fixed_role_projection_manifest(
            role="plamen_package", source_commit=source_commit,
            authority={
                "schema": "plamen.runtime-source-projection.v1",
                "sha256": manifest_row["sha256"],
                "size": manifest_row["size"],
            }, rows=projection_rows,
        )
        package_result = _write_and_seal_fixed_role_projection(
            source_roster=source_roster, private_store=private_store,
            role="plamen_package", manifest_raw=package_manifest,
            member_fds=ordered_fds,
        )
        return MappingProxyType({
            "plamen_guest": guest_result,
            "plamen_package": package_result,
        })
    finally:
        for descriptor in package_fds:
            os.close(descriptor)
        for descriptor in (package_root_fd, bootstrap_fd, runtime_manifest_fd):
            if descriptor >= 0:
                os.close(descriptor)


class _RetainedProductionBackendRoles:
    """Own the native-signed dynamic role-5/6 descriptor projection."""

    __slots__ = (
        "_records", "_input_authority", "_owned", "_identities", "_closed",
    )
    _PLAMEN_RETAINED_PRODUCTION_BACKEND_ROLES_V1 = True

    def __init__(
        self, *, records: tuple[MappingProxyType, ...],
        input_authority: Any, owned: list[int],
    ) -> None:
        if (
            len(records) != 2
            or tuple(row.get("role") for row in records) != (5, 6)
            or tuple(row.get("selector") for row in records)
            != ("codex", "claude")
        ):
            raise BuildError("production backend role roster differs")
        self._records = records
        self._input_authority = input_authority
        self._owned = owned
        descriptors = {
            row[field]
            for row in records
            for field in (
                "payload_fd", "producer_receipt_fd", "source_manifest_fd",
            )
        }
        descriptors.update(owned)
        self._identities = {}
        for descriptor in descriptors:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_size <= 0
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise BuildError("production backend role descriptor differs")
            self._identities[descriptor] = _identity(
                info, _sha256_fd(descriptor, info.st_size),
            )
        self._closed = False

    def role_records(self) -> tuple[MappingProxyType, ...]:
        if self._closed:
            raise BuildError("production backend role authority is closed")
        for descriptor, expected in self._identities.items():
            info = os.fstat(descriptor)
            if _identity(info, _sha256_fd(descriptor, info.st_size)) != expected:
                raise BuildError("production backend role descriptor changed")
        return self._records

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        for descriptor in reversed(self._owned):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._owned = []
        self._identities = {}
        close = getattr(self._input_authority, "close", None)
        if not callable(close):
            raise BuildError("production backend input custody differs")
        result = close()
        if result not in {None, True}:
            raise BuildError("production backend input custody did not close")
        return True


class _RetainedProductionEVMStaticUpstreams:
    """Own the four unlinked setup inputs consumed by role-8/9 native issue."""

    __slots__ = ("_fds", "_identities", "_closed")
    _PLAMEN_RETAINED_EVM_STATIC_UPSTREAMS_V1 = True

    def __init__(self, descriptors: tuple[int, int, int, int]) -> None:
        if (
            type(descriptors) is not tuple or len(descriptors) != 4
            or len(set(descriptors)) != 4
        ):
            raise BuildError("production EVM static upstream roster differs")
        self._fds = descriptors
        self._identities: dict[int, dict[str, Any]] = {}
        for descriptor in descriptors:
            if type(descriptor) is not int or descriptor < 3:
                raise BuildError("production EVM static upstream descriptor differs")
            info = os.fstat(descriptor)
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL) if fcntl else -1
            descriptor_flags = (
                fcntl.fcntl(descriptor, fcntl.F_GETFD) if fcntl else 0
            )
            if (
                flags & os.O_ACCMODE != os.O_RDONLY
                or not descriptor_flags & fcntl.FD_CLOEXEC
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 0
                or info.st_uid != os.geteuid() or info.st_size <= 0
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise BuildError("production EVM static upstream descriptor differs")
            self._identities[descriptor] = _identity(
                info, _sha256_fd(descriptor, info.st_size),
            )
        self._closed = False

    def descriptors(self) -> tuple[int, int, int, int]:
        if self._closed:
            raise BuildError("production EVM static upstream authority is closed")
        for descriptor, expected in self._identities.items():
            info = os.fstat(descriptor)
            if _identity(info, _sha256_fd(descriptor, info.st_size)) != expected:
                raise BuildError("production EVM static upstream descriptor changed")
        return self._fds

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        for descriptor in reversed(self._fds):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._fds = (-1, -1, -1, -1)
        self._identities = {}
        return True


class _RetainedProductionEVMStaticRoles:
    """Own the descriptor-replayed native role-8/9 installed leaves."""

    __slots__ = ("_records", "_identities", "_closed")
    _PLAMEN_RETAINED_PRODUCTION_EVM_STATIC_ROLES_V1 = True

    def __init__(self, records: tuple[MappingProxyType, MappingProxyType]) -> None:
        if (
            type(records) is not tuple or len(records) != 2
            or tuple(row.get("role") for row in records) != (8, 9)
            or tuple(row.get("name") for row in records)
            != ("medusa", "solc_amd64")
        ):
            raise BuildError("production EVM static role roster differs")
        self._records = records
        self._identities = {}
        for row in records:
            for field in (
                "payload_fd", "producer_receipt_fd", "source_manifest_fd",
            ):
                descriptor = row[field]
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_size <= 0
                    or stat.S_IMODE(info.st_mode) != 0o400
                ):
                    raise BuildError("production EVM static role descriptor differs")
                self._identities[descriptor] = _identity(
                    info, _sha256_fd(descriptor, info.st_size),
                )
        self._closed = False

    def role_records(self) -> tuple[MappingProxyType, MappingProxyType]:
        if self._closed:
            raise BuildError("production EVM static role authority is closed")
        for descriptor, expected in self._identities.items():
            info = os.fstat(descriptor)
            if _identity(info, _sha256_fd(descriptor, info.st_size)) != expected:
                raise BuildError("production EVM static role descriptor changed")
        return self._records

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        for descriptor in reversed(tuple(self._identities)):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._identities = {}
        return True


def _fetch_exact_setup_upstream(
    url: str, *, writer_fd: int, expected_size: int, expected_sha256: str,
    initial_host: str, redirect_hosts: tuple[str, ...],
    maximum_redirects: int,
) -> bool:
    """Stream one policy-bound setup object into an unlinked retained vnode.

    Redirect locations carry no content authority: they are restricted to the
    reviewed distribution hosts, receive no credentials, and the resulting
    byte stream must still match the exact frozen size and SHA-256 before it
    can reach a native producer.
    """

    import ssl
    import urllib.error
    import urllib.parse
    import urllib.request

    if (
        type(url) is not str or type(initial_host) is not str
        or type(redirect_hosts) is not tuple
        or any(type(host) is not str or not host for host in redirect_hosts)
        or type(expected_size) is not int
        or not 0 < expected_size <= 512 * 1024 * 1024
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "") is None
        or type(maximum_redirects) is not int
        or not 0 <= maximum_redirects <= 5
        or type(writer_fd) is not int or writer_fd < 3
    ):
        raise BuildError("production setup upstream request differs")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https" or parsed.hostname != initial_host
        or parsed.username is not None or parsed.password is not None
        or parsed.fragment
    ):
        raise BuildError("production setup upstream endpoint differs")
    before = os.fstat(writer_fd)
    flags = fcntl.fcntl(writer_fd, fcntl.F_GETFL) if fcntl else -1
    descriptor_flags = fcntl.fcntl(writer_fd, fcntl.F_GETFD) if fcntl else 0
    if (
        flags & os.O_ACCMODE != os.O_RDWR
        or not descriptor_flags & fcntl.FD_CLOEXEC
        or not stat.S_ISREG(before.st_mode) or before.st_nlink != 0
        or before.st_uid != os.geteuid() or before.st_size != 0
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise BuildError("production setup upstream writer differs")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    current = url
    digest = hashlib.sha256()
    total = 0
    try:
        for attempt in range(maximum_redirects + 1):
            request = urllib.request.Request(
                current,
                headers={
                    "Accept-Encoding": "identity",
                    "User-Agent": "plamen-native-setup/1",
                }, method="GET",
            )
            try:
                response = opener.open(request, timeout=60)
            except urllib.error.HTTPError as error:
                if error.code not in {301, 302, 303, 307, 308}:
                    raise
                location = error.headers.get("Location")
                error.close()
                if attempt >= maximum_redirects or not location:
                    raise BuildError("production setup redirect policy differs")
                redirected = urllib.parse.urlsplit(
                    urllib.parse.urljoin(current, location)
                )
                if (
                    redirected.scheme != "https"
                    or redirected.hostname not in redirect_hosts
                    or redirected.username is not None
                    or redirected.password is not None or redirected.fragment
                ):
                    raise BuildError("production setup redirect escaped authority")
                current = urllib.parse.urlunsplit(redirected)
                continue
            with response:
                if (
                    getattr(response, "status", 200) != 200
                    or response.geturl() != current
                    or response.headers.get("Content-Encoding")
                    not in {None, "identity"}
                ):
                    raise BuildError("production setup response authority differs")
                length = response.headers.get("Content-Length")
                if length is not None and (
                    not length.isdigit() or int(length) != expected_size
                ):
                    raise BuildError("production setup response size differs")
                while total < expected_size:
                    block = response.read(min(1024 * 1024, expected_size - total))
                    if not block:
                        break
                    _write_all(writer_fd, block)
                    digest.update(block); total += len(block)
                if response.read(1):
                    raise BuildError("production setup response exceeded bound")
                break
        else:  # pragma: no cover - loop always exits by return/exception
            raise BuildError("production setup redirect policy differs")
    except BuildError:
        raise
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise BuildError("production setup upstream transport failed") from exc
    after = os.fstat(writer_fd)
    if (
        (before.st_dev, before.st_ino, before.st_uid, before.st_nlink)
        != (after.st_dev, after.st_ino, after.st_uid, after.st_nlink)
        or total != expected_size or after.st_size != expected_size
        or digest.hexdigest() != expected_sha256
    ):
        raise BuildError("production setup upstream bytes differ")
    os.fsync(writer_fd)
    return True


def _acquire_production_evm_static_upstreams(
    *, source_freeze: dict[str, Any],
    source_roster: _RetainedFrozenSourceRoster, private_store: Any,
    builder_callbacks: MappingProxyType,
) -> _RetainedProductionEVMStaticUpstreams:
    """Acquire exact setup-only Medusa/solc inputs into anonymous stores."""

    fetch = builder_callbacks.get("fetch_exact_setup_upstream")
    pair = getattr(private_store, "pair", None)
    if (
        type(builder_callbacks).__name__ != "mappingproxy"
        or type(source_freeze) is not dict or not callable(fetch)
        or not callable(pair)
        or getattr(
            source_roster, "_PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1", None,
        ) is not True
    ):
        raise BuildError("production EVM static acquisition inputs differ")

    policy_fds: list[int] = []
    readers: list[int] = []
    writers: list[int] = []
    try:
        policies: dict[str, dict[str, Any]] = {}
        for role, source_role, schema in (
            ("medusa", "medusa_acquisition_policy", "plamen.medusa-acquisition.v1"),
            (
                "solc_amd64", "solc_amd64_acquisition_policy",
                "plamen.solc-amd64-acquisition-policy.v1",
            ),
        ):
            descriptor = source_roster.duplicate_member(source_role)
            policy_fds.append(descriptor)
            raw = _read_fd(
                descriptor, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                f"production {role} acquisition policy",
            )
            try:
                value = json.loads(raw.decode("ascii", "strict"))
            except (UnicodeError, ValueError):
                raise BuildError(
                    f"production {role} acquisition policy is malformed"
                ) from None
            frozen = next((
                row for row in source_freeze.get("sources", ())
                if type(row) is dict and row.get("role") == source_role
            ), None)
            if (
                type(value) is not dict or value.get("schema") != schema
                or raw != json.dumps(
                    value, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii") + b"\n"
                or type(frozen) is not dict
                or frozen.get("size") != len(raw)
                or frozen.get("sha256") != hashlib.sha256(raw).hexdigest()
            ):
                raise BuildError(f"production {role} acquisition policy differs")
            policies[role] = value

        medusa_artifact = policies["medusa"].get("artifact")
        solc_artifact = policies["solc_amd64"].get("artifact")
        if type(medusa_artifact) is not dict or type(solc_artifact) is not dict:
            raise BuildError("production EVM static artifact policy differs")
        medusa_archive = medusa_artifact.get("archive")
        medusa_bundle = (
            medusa_artifact.get("sigstore", {}).get("bundle")
            if type(medusa_artifact.get("sigstore")) is dict else None
        )
        solc_index = solc_artifact.get("provider_index")
        solc_binary = solc_artifact.get("binary")
        if any(type(row) is not dict for row in (
            medusa_archive, medusa_bundle, solc_index, solc_binary,
        )):
            raise BuildError("production EVM static retained input policy differs")
        requests = (
            (
                "medusa-archive", medusa_archive, "github.com",
                ("github.com", "objects.githubusercontent.com",
                 "release-assets.githubusercontent.com"), 5,
            ),
            (
                "medusa-sigstore", medusa_bundle, "github.com",
                ("github.com", "objects.githubusercontent.com",
                 "release-assets.githubusercontent.com"), 5,
            ),
            (
                "solc-provider-index", solc_index,
                "binaries.soliditylang.org", ("binaries.soliditylang.org",), 1,
            ),
            (
                "solc-binary", solc_binary,
                "binaries.soliditylang.org", ("binaries.soliditylang.org",), 1,
            ),
        )
        for label, row, initial_host, redirect_hosts, maximum_redirects in requests:
            if (
                not {"url", "size", "sha256"} <= set(row)
                or type(row.get("url")) is not str
                or type(row.get("size")) is not int
                or re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) is None
            ):
                raise BuildError("production EVM static request policy differs")
            writer, reader = pair("upstream-" + label, linked=False)
            writers.append(writer); readers.append(reader)
            if fetch(
                row["url"], writer_fd=writer, expected_size=row["size"],
                expected_sha256=row["sha256"], initial_host=initial_host,
                redirect_hosts=redirect_hosts,
                maximum_redirects=maximum_redirects,
            ) is not True:
                raise BuildError("production EVM static upstream fetch was rejected")
            os.close(writer); writers.remove(writer)
            info = os.fstat(reader)
            if (
                info.st_size != row["size"]
                or _sha256_fd(reader, info.st_size) != row["sha256"]
            ):
                raise BuildError("production EVM static upstream replay differs")
        return _RetainedProductionEVMStaticUpstreams(tuple(readers))
    except BaseException:
        for descriptor in [*writers, *readers]:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    finally:
        for descriptor in policy_fds:
            os.close(descriptor)


def _issue_production_native_evm_static_roles(
    *, source_freeze: dict[str, Any],
    source_roster: _RetainedFrozenSourceRoster,
    compiled_artifacts: dict[str, dict[str, Any]],
    staged_generation_root_fd: int,
    upstream_authority: _RetainedProductionEVMStaticUpstreams,
    builder_callbacks: MappingProxyType,
) -> _RetainedProductionEVMStaticRoles:
    """Issue role-8/9 and independently replay every installed leaf/footer."""

    runner = builder_callbacks.get("run_native_evm_static_acquisition")
    if (
        type(builder_callbacks).__name__ != "mappingproxy"
        or type(source_freeze) is not dict or not callable(runner)
        or type(compiled_artifacts) is not dict
        or getattr(
            source_roster, "_PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1", None,
        ) is not True
        or getattr(
            upstream_authority,
            "_PLAMEN_RETAINED_EVM_STATIC_UPSTREAMS_V1", None,
        ) is not True
        or type(staged_generation_root_fd) is not int
        or staged_generation_root_fd < 3
    ):
        raise BuildError("production EVM static native issue inputs differ")
    coordinator = compiled_artifacts.get("retained-source-bootstrap-coordinator")
    if type(coordinator) is not dict:
        raise BuildError("production EVM static coordinator is absent")
    executable, executable_fd = coordinator.get("path"), coordinator.get("fd")
    if not isinstance(executable, Path) or type(executable_fd) is not int:
        raise BuildError("production EVM static coordinator differs")
    root_before = os.fstat(staged_generation_root_fd)
    root_flags = fcntl.fcntl(staged_generation_root_fd, fcntl.F_GETFL) if fcntl else -1
    root_fd_flags = fcntl.fcntl(staged_generation_root_fd, fcntl.F_GETFD) if fcntl else 0
    if (
        root_flags & os.O_ACCMODE != os.O_RDONLY
        or not root_fd_flags & fcntl.FD_CLOEXEC
        or not stat.S_ISDIR(root_before.st_mode)
        or root_before.st_uid != os.geteuid()
        or stat.S_IMODE(root_before.st_mode) != 0o700
    ):
        raise BuildError("production EVM static stage root differs")

    opened: list[int] = []
    frozen: list[int] = []
    try:
        upstreams = upstream_authority.descriptors()
        if runner(
            executable, staged_generation_root_fd=staged_generation_root_fd,
            medusa_archive_fd=upstreams[0],
            medusa_sigstore_bundle_fd=upstreams[1],
            solc_provider_index_fd=upstreams[2],
            solc_binary_fd=upstreams[3], executable_fd=executable_fd,
        ) is not True:
            raise BuildError("production EVM static native issue was rejected")
        if _directory_anchor(root_before) != _directory_anchor(
            os.fstat(staged_generation_root_fd)
        ):
            raise BuildError("production EVM static stage root changed")

        results: list[MappingProxyType] = []
        for ordinal, name, validator, policy_role, receipt_role, manifest_role in (
            (8, "medusa", 6, "medusa_acquisition_policy",
             "medusa_acquisition_receipt", "medusa_runtime_source_manifest"),
            (9, "solc_amd64", 7, "solc_amd64_acquisition_policy",
             "solc_amd64_acquisition_receipt", "solc_amd64_runtime_source_manifest"),
        ):
            source_fds = [
                source_roster.duplicate_member(role)
                for role in (policy_role, receipt_role, manifest_role)
            ]
            frozen.extend(source_fds)
            policy_raw = _read_fd(
                source_fds[0], PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                f"production {name} policy",
            )
            receipt_prefix = _read_fd(
                source_fds[1], PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                f"production {name} semantic receipt",
            )
            manifest_raw = _read_fd(
                source_fds[2], PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                f"production {name} source manifest",
            )
            try:
                policy = json.loads(policy_raw)
                receipt = json.loads(receipt_prefix)
                manifest = json.loads(manifest_raw)
            except (UnicodeError, ValueError):
                raise BuildError(
                    f"production {name} frozen authority is malformed"
                ) from None
            expected_schema = (
                "plamen.medusa-acquisition-receipt.v1" if ordinal == 8
                else "plamen.solc-amd64-acquisition-receipt.v1"
            )
            artifact = policy.get("artifact") if type(policy) is dict else None
            payload = (
                artifact.get("executable") if ordinal == 8
                else artifact.get("binary")
            ) if type(artifact) is dict else None
            if (
                type(payload) is not dict or type(receipt) is not dict
                or receipt.get("schema") != expected_schema
                or type(manifest) is not dict
                or not policy_raw.endswith(b"\n")
                or not manifest_raw.endswith(b"\n")
                or receipt_prefix.endswith(b"\n")
            ):
                raise BuildError(f"production {name} frozen authority differs")
            policy_sha = hashlib.sha256(policy_raw).hexdigest()
            receipt_sha = hashlib.sha256(receipt_prefix).hexdigest()
            manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
            expected_rows = {
                role: next((
                    row for row in source_freeze.get("sources", ())
                    if type(row) is dict and row.get("role") == role
                ), None)
                for role in (policy_role, receipt_role, manifest_role)
            }
            if any(type(row) is not dict for row in expected_rows.values()) or (
                expected_rows[policy_role].get("sha256") != policy_sha
                or expected_rows[policy_role].get("size") != len(policy_raw)
                or expected_rows[receipt_role].get("sha256") != receipt_sha
                or expected_rows[receipt_role].get("size") != len(receipt_prefix)
                or expected_rows[manifest_role].get("sha256") != manifest_sha
                or expected_rows[manifest_role].get("size") != len(manifest_raw)
            ):
                raise BuildError(f"production {name} frozen identity differs")

            base = "share/plamen/native-source-authority-v1"
            payload_fd = _open_relative_nofollow(
                staged_generation_root_fd,
                f"{base}/{ordinal:02d}-{name}.payload", directory=False,
            )
            producer_fd = _open_relative_nofollow(
                staged_generation_root_fd,
                f"{base}/{ordinal:02d}-{name}.producer-receipt",
                directory=False,
            )
            manifest_fd = _open_relative_nofollow(
                staged_generation_root_fd,
                f"{base}/{ordinal:02d}-{name}.source-manifest",
                directory=False,
            )
            opened.extend((payload_fd, producer_fd, manifest_fd))
            payload_info = os.fstat(payload_fd)
            producer_info = os.fstat(producer_fd)
            manifest_info = os.fstat(manifest_fd)
            payload_size, payload_sha = payload.get("size"), payload.get("sha256")
            producer_raw = _read_fd(
                producer_fd, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                f"production {name} producer receipt",
            )
            if (
                any(
                    stat.S_IMODE(info.st_mode) != 0o400
                    or info.st_uid != os.geteuid() or info.st_nlink != 1
                    for info in (payload_info, producer_info, manifest_info)
                )
                or type(payload_size) is not int or payload_size <= 0
                or re.fullmatch(r"[0-9a-f]{64}", payload_sha or "") is None
                or payload_info.st_size != payload_size
                or _sha256_fd(payload_fd, payload_info.st_size) != payload_sha
                or manifest_info.st_size != len(manifest_raw)
                or _sha256_fd(manifest_fd, manifest_info.st_size) != manifest_sha
                or len(producer_raw) != len(receipt_prefix) + 512
                or producer_raw[:-512] != receipt_prefix
            ):
                raise BuildError(f"production {name} installed leaf differs")
            footer = producer_raw[-512:]
            if (
                footer[:8] != b"PLMOP4R1"
                or struct.unpack_from(">HHHHH", footer, 8)
                != (1, 512, ordinal, 1, validator)
                or struct.unpack_from(">QQQ", footer, 20)
                != (payload_size, len(manifest_raw), len(receipt_prefix))
                or footer[44:76].hex() != policy_sha
                or footer[76:108].hex() != payload_sha
                or footer[108:140].hex() != manifest_sha
                or footer[140:172].hex() != receipt_sha
                or footer[172:268].split(b"\0", 1)[0].decode(
                    "ascii", "strict",
                ) != expected_schema
                or any(footer[268:480])
                or footer[480:] != hashlib.sha256(footer[:480]).digest()
            ):
                raise BuildError(f"production {name} native footer differs")
            results.append(MappingProxyType({
                "name": name, "role": ordinal,
                "payload_fd": payload_fd,
                "producer_receipt_fd": producer_fd,
                "source_manifest_fd": manifest_fd,
                "policy_sha256": policy_sha,
            }))
        authority = _RetainedProductionEVMStaticRoles(tuple(results))
        opened.clear()
        if upstream_authority.close() is not True:
            raise BuildError("production EVM static upstream custody did not close")
        return authority
    except BaseException:
        for descriptor in opened:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            upstream_authority.close()
        except BaseException:
            pass
        raise
    finally:
        for descriptor in frozen:
            os.close(descriptor)


def _retained_backend_input_records(authority: Any) -> tuple[dict[str, Any], ...]:
    records = getattr(authority, "records", None)
    if (
        getattr(authority, "_PLAMEN_PRODUCTION_BACKEND_INPUTS_V1", None)
        is not True or not callable(records)
        or not callable(getattr(authority, "close", None))
    ):
        raise BuildError("production backend input authority differs")
    value = records()
    if type(value) is not tuple or len(value) != 2:
        raise BuildError("production backend input roster differs")
    normalized: list[dict[str, Any]] = []
    descriptors: set[int] = set()
    for expected_selector, expected_role, row in zip(
        ("codex", "claude"), (5, 6), value, strict=True,
    ):
        if (
            type(row) is not dict
            or set(row) != {
                "selector", "role", "unsigned_receipt_fd", "payload_fd",
                "source_manifest_fd",
            }
            or row.get("selector") != expected_selector
            or row.get("role") != expected_role
        ):
            raise BuildError("production backend input row differs")
        for field in (
            "unsigned_receipt_fd", "payload_fd", "source_manifest_fd",
        ):
            descriptor = row[field]
            if (
                type(descriptor) is not int or descriptor < 3
                or descriptor in descriptors
            ):
                raise BuildError("production backend input descriptor differs")
            descriptors.add(descriptor)
            info = os.fstat(descriptor)
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL) if fcntl else -1
            descriptor_flags = (
                fcntl.fcntl(descriptor, fcntl.F_GETFD) if fcntl else 0
            )
            if (
                flags & os.O_ACCMODE != os.O_RDONLY
                or not descriptor_flags & fcntl.FD_CLOEXEC
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_size <= 0
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise BuildError("production backend input authority differs")
        normalized.append(dict(row))
    return tuple(normalized)


def _issue_production_native_backend_roles(
    *, source_freeze: dict[str, Any],
    source_roster: _RetainedFrozenSourceRoster,
    compiled_artifacts: dict[str, dict[str, Any]], private_store: Any,
    input_authority: Any, builder_callbacks: MappingProxyType,
) -> _RetainedProductionBackendRoles:
    """Native-sign and re-admit retained Codex/Claude operation-4 rows.

    Resolution/download/probing is intentionally outside this function and
    enters only as an opaque descriptor authority.  The install coordinator's
    signer publishes one key and both semantic receipts; the frozen Python
    validator then independently authenticates the resulting key, receipt,
    payload, and source-manifest descriptors before they may join operation 4.
    """

    if (
        type(builder_callbacks).__name__ != "mappingproxy"
        or type(source_freeze) is not dict
        or type(compiled_artifacts) is not dict
        or getattr(
            source_roster, "_PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1", None,
        ) is not True
    ):
        raise BuildError("production backend signer inputs differ")
    run_signer = builder_callbacks.get("run_native_backend_receipt_signer")
    binder = builder_callbacks.get("bind_retained_backend_generation")
    pair = getattr(private_store, "pair", None)
    if not callable(run_signer) or not callable(binder) or not callable(pair):
        raise BuildError("production backend signer operations are absent")
    inputs = _retained_backend_input_records(input_authority)
    coordinator = compiled_artifacts.get("retained-source-bootstrap-coordinator")
    if type(coordinator) is not dict:
        raise BuildError("production backend signer executable is absent")
    executable_fd = coordinator.get("fd", -1)
    executable_path = coordinator.get("path")
    if (
        type(executable_fd) is not int or executable_fd < 3
        or not isinstance(executable_path, Path)
    ):
        raise BuildError("production backend signer executable differs")

    policy_fd = -1
    owned: list[int] = []
    writers: list[int] = []
    try:
        policy_fd = source_roster.duplicate_member(
            "native_backend_latest_acquisition_policy"
        )
        policy_raw = _read_fd(
            policy_fd, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
            "production backend acquisition policy",
        )
        try:
            policy = json.loads(policy_raw.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise BuildError("production backend acquisition policy is malformed") from None
        policy_sha256 = hashlib.sha256(policy_raw).hexdigest()
        policy_row = next((
            row for row in source_freeze.get("sources", ())
            if type(row) is dict
            and row.get("role") == "native_backend_latest_acquisition_policy"
        ), None)
        if (
            type(policy_row) is not dict
            or policy_row.get("sha256") != policy_sha256
            or policy_row.get("size") != len(policy_raw)
            or not policy_raw.endswith(b"\n")
            or json.dumps(
                policy, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8") + b"\n" != policy_raw
        ):
            raise BuildError("production backend acquisition policy differs")

        public_writer, public_reader = pair(
            "backend-generation-verifier-key", linked=True,
        )
        writers.append(public_writer); owned.append(public_reader)
        semantic_pairs: list[tuple[int, int]] = []
        backend_rows: list[tuple[int, int, int, int, int]] = []
        for row in inputs:
            writer, reader = pair(
                f"backend-{row['selector']}-semantic-receipt", linked=True,
            )
            writers.append(writer); owned.append(reader)
            semantic_pairs.append((writer, reader))
            backend_rows.append((
                row["unsigned_receipt_fd"], row["payload_fd"],
                row["source_manifest_fd"], writer, reader,
            ))
        if run_signer(
            executable_path, public_key_pair=(public_writer, public_reader),
            backend_rows=backend_rows, executable_fd=executable_fd,
        ) is not True:
            raise BuildError("production backend native signer was rejected")
        for writer in writers:
            os.close(writer)
        writers.clear()
        public_raw = _read_fd(
            public_reader, 32, "production backend verifier key",
        )
        if len(public_raw) != 32:
            raise BuildError("production backend verifier key differs")

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        public_key = Ed25519PublicKey.from_public_bytes(public_raw)

        def verifier(raw: bytes, authentication: Any) -> bool:
            try:
                if (
                    type(authentication) is not dict
                    or authentication.get("key_id")
                    != hashlib.sha256(public_raw).hexdigest()
                ):
                    return False
                public_key.verify(
                    bytes.fromhex(authentication["signature"]), raw,
                )
                return True
            except (InvalidSignature, KeyError, TypeError, ValueError):
                return False

        results: list[MappingProxyType] = []
        for row, (_writer, semantic_fd) in zip(
            inputs, semantic_pairs, strict=True,
        ):
            semantic = _read_fd(
                semantic_fd, 64 * 1024 * 1024,
                f"production {row['selector']} semantic receipt",
            )
            if len(semantic) <= 512 or semantic[-512:-504] != b"PLMOP4R1":
                raise BuildError("production backend native receipt footer differs")
            try:
                receipt = json.loads(semantic[:-512].decode("utf-8"))
            except (UnicodeError, ValueError):
                raise BuildError("production backend native receipt is malformed") from None
            if (
                type(receipt) is not dict
                or receipt.get("selector") != row["selector"]
                or json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8") != semantic[:-512]
            ):
                raise BuildError("production backend native receipt differs")
            authority = binder(
                source_freeze=source_freeze, receipt=receipt,
                policy=policy, policy_sha256=policy_sha256,
                verifier=verifier, payload_fd=row["payload_fd"],
                semantic_receipt_fd=semantic_fd,
                source_manifest_fd=row["source_manifest_fd"],
                verifier_public_key_fd=public_reader,
            )
            generation = getattr(authority, "generation", None)
            if (
                generation is None
                or getattr(generation, "selector", None) != row["selector"]
                or getattr(authority, "payload_fd", None) != row["payload_fd"]
                or getattr(authority, "semantic_receipt_fd", None) != semantic_fd
                or getattr(authority, "source_manifest_fd", None)
                != row["source_manifest_fd"]
                or getattr(authority, "verifier_public_key_fd", None)
                != public_reader
            ):
                raise BuildError("production backend retained admission differs")
            results.append(MappingProxyType({
                "selector": row["selector"], "role": row["role"],
                "payload_fd": row["payload_fd"],
                "producer_receipt_fd": semantic_fd,
                "source_manifest_fd": row["source_manifest_fd"],
                "policy_sha256": policy_sha256, "authority": authority,
            }))
        return _RetainedProductionBackendRoles(
            records=tuple(results), input_authority=input_authority,
            owned=owned,
        )
    except BaseException:
        for descriptor in writers:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for descriptor in reversed(owned):
            try:
                os.close(descriptor)
            except OSError:
                pass
        close = getattr(input_authority, "close", None)
        if callable(close):
            close()
        raise
    finally:
        if policy_fd >= 0:
            os.close(policy_fd)


def _operation4_policy_row_from_retained_record(
    *, role: int, payload_fd: int, producer_receipt_fd: int,
    source_manifest_fd: int, policy_sha256: str,
) -> dict[str, Any]:
    """Recompute one operation-4 policy row from its retained native receipt."""

    if (
        type(role) is not int or not 0 <= role < _OPERATION4_ROLE_COUNT
        or any(
            type(descriptor) is not int or descriptor < 3
            for descriptor in (
                payload_fd, producer_receipt_fd, source_manifest_fd,
            )
        )
        or len({payload_fd, producer_receipt_fd, source_manifest_fd}) != 3
        or re.fullmatch(r"[0-9a-f]{64}", policy_sha256 or "") is None
        or policy_sha256 == "0" * 64
    ):
        raise BuildError("operation-4 retained role binding differs")
    infos = [
        os.fstat(descriptor) for descriptor in (
            payload_fd, producer_receipt_fd, source_manifest_fd,
        )
    ]
    if any(
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or info.st_uid != os.geteuid() or info.st_size <= 0
        or stat.S_IMODE(info.st_mode) & 0o022
        for info in infos
    ):
        raise BuildError("operation-4 retained role descriptor differs")
    payload_info, producer_info, manifest_info = infos
    if producer_info.st_size <= 512:
        raise BuildError("operation-4 retained producer receipt is truncated")
    footer = os.pread(producer_receipt_fd, 512, producer_info.st_size - 512)
    if len(footer) != 512:
        raise BuildError("operation-4 retained producer footer is truncated")
    semantic_size = producer_info.st_size - 512
    schema_raw = footer[172:268].split(b"\0", 1)[0]
    try:
        schema = schema_raw.decode("ascii", "strict")
    except UnicodeError:
        raise BuildError("operation-4 retained receipt schema differs") from None
    expected_mode = _OPERATION4_IDENTITY_MODES[role]
    expected_validator = _OPERATION4_RECEIPT_VALIDATORS[role]
    expected_schema = _OPERATION4_POLICY_SCHEMAS[role]
    payload_sha256 = _sha256_fd(payload_fd, payload_info.st_size)
    manifest_sha256 = _sha256_fd(
        source_manifest_fd, manifest_info.st_size,
    )
    semantic_sha256 = _sha256_prefix_fd(
        producer_receipt_fd, semantic_size,
    )
    if (
        footer[:8] != b"PLMOP4R1"
        or struct.unpack_from(">HHHHH", footer, 8) != (
            1, 512, role, expected_mode, expected_validator,
        )
        or struct.unpack_from(">QQQ", footer, 20) != (
            payload_info.st_size, manifest_info.st_size, semantic_size,
        )
        or footer[44:76].hex() != policy_sha256
        or footer[76:108].hex() != payload_sha256
        or footer[108:140].hex() != manifest_sha256
        or footer[140:172].hex() != semantic_sha256
        or schema != expected_schema
        or footer[480:] != hashlib.sha256(footer[:480]).digest()
    ):
        raise BuildError("operation-4 retained producer authority differs")
    dynamic = role in {5, 6}
    return {
        "role": role, "identity_mode": expected_mode,
        "receipt_validator": expected_validator,
        "payload_size": 0 if dynamic else payload_info.st_size,
        "source_manifest_size": 0 if dynamic else manifest_info.st_size,
        "semantic_receipt_size": 0 if dynamic else semantic_size,
        "payload_sha256": "0" * 64 if dynamic else payload_sha256,
        "source_manifest_sha256": (
            "0" * 64 if dynamic else manifest_sha256
        ),
        "semantic_receipt_sha256": (
            "0" * 64 if dynamic else semantic_sha256
        ),
        "policy_sha256": policy_sha256,
        "receipt_schema": expected_schema,
    }


def _derive_production_operation4_policy_rows(
    *, source_freeze: dict[str, Any],
    source_roster: _RetainedFrozenSourceRoster,
    fixed_materialized_inputs: object,
) -> tuple[MappingProxyType, ...]:
    """Derive the compile policy before the standalone signer exists.

    Fixed roles enter through the materializer's retained descriptors.  The
    two latest-backend rows deliberately bind only the reviewed acquisition
    policy; their acquired bytes and resolved versions are authenticated by
    their signed receipts at issuance time.  The role-8/9 facts come from the
    frozen renderer whose setup transport was independently bound above.
    """

    if (
        type(source_freeze) is not dict
        or getattr(
            source_roster, "_PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1", None,
        ) is not True
        or type(fixed_materialized_inputs) is not tuple
        or len(fixed_materialized_inputs) != 7
    ):
        raise BuildError("operation-4 compile policy inputs differ")
    rows: dict[int, dict[str, Any]] = {}
    descriptors: set[int] = set()
    for expected, value in zip(
        (0, 1, 2, 3, 4, 7, 10), fixed_materialized_inputs, strict=True,
    ):
        ordinal = getattr(value, "ordinal", None)
        payload_fd = getattr(value, "payload_fd", None)
        semantic_fd = getattr(value, "semantic_receipt_fd", None)
        manifest_fd = getattr(value, "source_manifest_fd", None)
        policy_fd = getattr(value, "reviewed_policy_fd", None)
        fds = (payload_fd, semantic_fd, manifest_fd, policy_fd)
        if (
            ordinal != expected
            or any(type(fd) is not int or fd < 3 or fd in descriptors for fd in fds)
        ):
            raise BuildError("operation-4 fixed materialized role differs")
        descriptors.update(fds)
        infos = [os.fstat(fd) for fd in fds]
        if any(
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_size <= 0
            or stat.S_IMODE(info.st_mode) & 0o022
            for info in infos
        ):
            raise BuildError("operation-4 fixed materialized descriptor differs")
        payload_info, semantic_info, manifest_info, policy_info = infos
        rows[expected] = {
            "role": expected,
            "identity_mode": _OPERATION4_IDENTITY_MODES[expected],
            "receipt_validator": _OPERATION4_RECEIPT_VALIDATORS[expected],
            "payload_size": payload_info.st_size,
            "source_manifest_size": manifest_info.st_size,
            "semantic_receipt_size": semantic_info.st_size,
            "payload_sha256": _sha256_fd(payload_fd, payload_info.st_size),
            "source_manifest_sha256": _sha256_fd(
                manifest_fd, manifest_info.st_size,
            ),
            "semantic_receipt_sha256": _sha256_fd(
                semantic_fd, semantic_info.st_size,
            ),
            "policy_sha256": _sha256_fd(policy_fd, policy_info.st_size),
            "receipt_schema": _OPERATION4_POLICY_SCHEMAS[expected],
        }

    policy_fd = -1
    try:
        policy_fd = source_roster.duplicate_member(
            "native_backend_latest_acquisition_policy"
        )
        policy_info = os.fstat(policy_fd)
        policy_sha256 = _sha256_fd(policy_fd, policy_info.st_size)
        frozen_policy = next((
            row for row in source_freeze.get("sources", ())
            if type(row) is dict
            and row.get("role") == "native_backend_latest_acquisition_policy"
        ), None)
        if (
            type(frozen_policy) is not dict
            or frozen_policy.get("size") != policy_info.st_size
            or frozen_policy.get("sha256") != policy_sha256
        ):
            raise BuildError("operation-4 backend policy differs")
        for role in (5, 6):
            rows[role] = {
                "role": role,
                "identity_mode": _OPERATION4_IDENTITY_MODES[role],
                "receipt_validator": _OPERATION4_RECEIPT_VALIDATORS[role],
                "payload_size": 0, "source_manifest_size": 0,
                "semantic_receipt_size": 0,
                "payload_sha256": "0" * 64,
                "source_manifest_sha256": "0" * 64,
                "semantic_receipt_sha256": "0" * 64,
                "policy_sha256": policy_sha256,
                "receipt_schema": _OPERATION4_POLICY_SCHEMAS[role],
            }
    finally:
        if policy_fd >= 0:
            os.close(policy_fd)

    for role, name, policy_role, receipt_role, manifest_role in (
        (8, "medusa", "medusa_acquisition_policy",
         "medusa_acquisition_receipt", "medusa_runtime_source_manifest"),
        (9, "solc_amd64", "solc_amd64_acquisition_policy",
         "solc_amd64_acquisition_receipt",
         "solc_amd64_runtime_source_manifest"),
    ):
        retained = [
            source_roster.duplicate_member(source_role)
            for source_role in (policy_role, receipt_role, manifest_role)
        ]
        try:
            policy_raw, receipt_raw, manifest_raw = (
                _read_fd(fd, PRODUCTION_SOURCE_MEMBER_MAX_BYTES,
                         f"operation-4 {name} compile policy")
                for fd in retained
            )
            try:
                policy_value = json.loads(policy_raw.decode("ascii", "strict"))
                receipt_value = json.loads(receipt_raw.decode("ascii", "strict"))
            except (UnicodeError, ValueError):
                raise BuildError("operation-4 EVM policy is malformed") from None
            artifact = (
                policy_value.get("artifact")
                if type(policy_value) is dict else None
            )
            payload = (
                artifact.get("executable" if role == 8 else "binary")
                if type(artifact) is dict else None
            )
            frozen = {
                row.get("role"): row for row in source_freeze.get("sources", ())
                if type(row) is dict
                and row.get("role") in {policy_role, receipt_role, manifest_role}
            }
            if (
                type(payload) is not dict
                or type(payload.get("size")) is not int
                or payload["size"] <= 0
                or re.fullmatch(r"[0-9a-f]{64}", payload.get("sha256", ""))
                is None
                or type(receipt_value) is not dict
                or receipt_value.get("schema") != _OPERATION4_POLICY_SCHEMAS[role]
                or not policy_raw.endswith(b"\n")
                or receipt_raw.endswith(b"\n")
                or not manifest_raw.endswith(b"\n")
                or set(frozen) != {policy_role, receipt_role, manifest_role}
                or any(
                    frozen[source_role].get("size") != len(raw)
                    or frozen[source_role].get("sha256")
                    != hashlib.sha256(raw).hexdigest()
                    for source_role, raw in (
                        (policy_role, policy_raw), (receipt_role, receipt_raw),
                        (manifest_role, manifest_raw),
                    )
                )
            ):
                raise BuildError("operation-4 EVM policy projection differs")
            rows[role] = {
                "role": role,
                "identity_mode": _OPERATION4_IDENTITY_MODES[role],
                "receipt_validator": _OPERATION4_RECEIPT_VALIDATORS[role],
                "payload_size": payload["size"],
                "source_manifest_size": len(manifest_raw),
                "semantic_receipt_size": len(receipt_raw),
                "payload_sha256": payload["sha256"],
                "source_manifest_sha256": hashlib.sha256(
                    manifest_raw,
                ).hexdigest(),
                "semantic_receipt_sha256": hashlib.sha256(
                    receipt_raw,
                ).hexdigest(),
                "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
                "receipt_schema": _OPERATION4_POLICY_SCHEMAS[role],
            }
        finally:
            for descriptor in retained:
                os.close(descriptor)
    if set(rows) != set(range(_OPERATION4_ROLE_COUNT)):
        raise BuildError("operation-4 compile policy denominator differs")
    ordered = [rows[role] for role in range(_OPERATION4_ROLE_COUNT)]
    _render_operation4_fixed_policy_source(ordered)
    return tuple(MappingProxyType(row) for row in ordered)


def _compose_production_operation4_inputs(
    *, fixed_role_records: object,
    backend_authority: _RetainedProductionBackendRoles,
    evm_static_authority: _RetainedProductionEVMStaticRoles,
) -> MappingProxyType:
    """Fold all eleven retained role triples into the exact op4 input order."""

    if (
        type(fixed_role_records) is not tuple or len(fixed_role_records) != 7
        or getattr(
            backend_authority,
            "_PLAMEN_RETAINED_PRODUCTION_BACKEND_ROLES_V1", None,
        ) is not True
        or getattr(
            evm_static_authority,
            "_PLAMEN_RETAINED_PRODUCTION_EVM_STATIC_ROLES_V1", None,
        ) is not True
    ):
        raise BuildError("operation-4 retained authority roster differs")
    fixed_ordinals = (0, 1, 2, 3, 4, 7, 10)
    records: dict[int, dict[str, Any]] = {}
    for expected, value in zip(fixed_ordinals, fixed_role_records, strict=True):
        observed = {
            "role": getattr(value, "ordinal", None),
            "payload_fd": getattr(value, "payload_fd", None),
            "producer_receipt_fd": getattr(value, "producer_receipt_fd", None),
            "source_manifest_fd": getattr(value, "source_manifest_fd", None),
            "policy_sha256": getattr(value, "policy_sha256", None),
        }
        if observed["role"] != expected:
            raise BuildError("operation-4 fixed role order differs")
        records[expected] = observed
    for authority, expected_roles in (
        (backend_authority, (5, 6)), (evm_static_authority, (8, 9)),
    ):
        values = authority.role_records()
        if type(values) is not tuple or len(values) != len(expected_roles):
            raise BuildError("operation-4 retained authority roster differs")
        for expected, value in zip(expected_roles, values, strict=True):
            if type(value) is not MappingProxyType:
                raise BuildError("operation-4 retained role record differs")
            required = {
                "role", "payload_fd", "producer_receipt_fd",
                "source_manifest_fd", "policy_sha256",
            }
            if value.get("role") != expected or not required <= set(value):
                raise BuildError("operation-4 retained role order differs")
            records[expected] = {field: value[field] for field in required}
    if set(records) != set(range(_OPERATION4_ROLE_COUNT)):
        raise BuildError("operation-4 retained role denominator differs")
    role_fds: list[tuple[int, int, int]] = []
    policy_rows: list[dict[str, Any]] = []
    descriptors: set[int] = set()
    for role in range(_OPERATION4_ROLE_COUNT):
        record = records[role]
        triple = (
            record["payload_fd"], record["producer_receipt_fd"],
            record["source_manifest_fd"],
        )
        if any(fd in descriptors for fd in triple):
            raise BuildError("operation-4 retained descriptors alias")
        descriptors.update(triple)
        role_fds.append(triple)
        policy_rows.append(_operation4_policy_row_from_retained_record(
            role=role, payload_fd=triple[0],
            producer_receipt_fd=triple[1], source_manifest_fd=triple[2],
            policy_sha256=record["policy_sha256"],
        ))
    # Reuse the final C-source renderer as an independent policy-shape and
    # roster-digest validator before a coordinator is ever compiled.
    _render_operation4_fixed_policy_source(policy_rows)
    return MappingProxyType({
        "policy_rows": tuple(MappingProxyType(row) for row in policy_rows),
        "role_fds": tuple(role_fds),
    })


class _RetainedProductionNativeTransaction:
    """Bind one opaque native acquisition authority to one cold install.

    The object deliberately knows nothing about acquisition paths or artifact
    bytes.  Its delegate must already own the retained descriptors needed to
    stage, validate, publish, validate-installed, compensate, and clean up the
    native generation.  This wrapper contributes the outer transaction's
    account/source bindings and rejects malformed stage authority before the
    durable coordinator may record it.
    """

    __slots__ = (
        "_home", "_source", "_authority", "_source_roster", "_closed",
        "_stages",
    )
    _PLAMEN_RETAINED_NATIVE_TRANSACTION_V1 = True

    def __init__(
        self, *, home: Path, source: dict[str, Any], authority: Any,
        source_roster: _RetainedFrozenSourceRoster,
    ) -> None:
        required = (
            "stage", "validate_stage", "commit", "validate_installed",
            "rollback", "cleanup", "close",
        )
        if (
            getattr(
                authority, "_PLAMEN_PRODUCTION_NATIVE_ACQUISITION_V1", None,
            ) is not True
            or any(not callable(getattr(authority, name, None)) for name in required)
            or getattr(
                source_roster, "_PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1", None,
            ) is not True
        ):
            raise BuildError("production native acquisition authority differs")
        self._home = home
        self._source = dict(source)
        self._authority = authority
        self._source_roster = source_roster
        self._closed = False
        self._stages: dict[str, dict[str, Any]] = {}

    def _operation(self, name: str) -> Any:
        if self._closed:
            raise BuildError("production native transaction is closed")
        operation = getattr(self._authority, name, None)
        if not callable(operation):
            raise BuildError("production native acquisition authority differs")
        return operation

    def _bind_home_source(
        self, home: Path, source: dict[str, Any],
    ) -> None:
        if home.absolute() != self._home or source != self._source:
            raise BuildError("production native transaction binding differs")

    @staticmethod
    def _validate_stage_authority(
        value: object, transaction_id: str,
    ) -> dict[str, Any]:
        if (
            type(value) is not dict
            or set(value) != {
                "schema", "kind", "transaction_id", "manifest_sha256",
                "artifact_count",
            }
            or value.get("schema") != "plamen.posix-native-install.stage.v1"
            or value.get("kind") != "native"
            or value.get("transaction_id") != transaction_id
            or re.fullmatch(r"[0-9a-f]{64}", value.get("manifest_sha256", ""))
            is None
            or type(value.get("artifact_count")) is not int
            or value["artifact_count"] <= 0
        ):
            raise BuildError("production native staged authority differs")
        return dict(value)

    def stage(
        self, home: Path, transaction_root: Path, source: dict[str, Any],
        package_stage: dict[str, Any],
    ) -> dict[str, Any]:
        self._bind_home_source(home, source)
        if (
            not transaction_root.is_absolute()
            or not transaction_root.is_dir()
            or re.fullmatch(r"[0-9a-f]{32}", transaction_root.name) is None
            or type(package_stage) is not dict
            or package_stage.get("transaction_id") != transaction_root.name
        ):
            raise BuildError("production native stage binding differs")
        observed = self._validate_stage_authority(
            self._operation("stage")(
                home, transaction_root, source, package_stage,
            ),
            transaction_root.name,
        )
        prior = self._stages.get(transaction_root.name)
        if prior is not None and prior != observed:
            raise BuildError("production native stage replay differs")
        self._stages[transaction_root.name] = observed
        return dict(observed)

    def validate_stage(
        self, stage: dict[str, Any], source: dict[str, Any],
        package_stage: dict[str, Any],
    ) -> bool:
        if source != self._source or type(package_stage) is not dict:
            raise BuildError("production native stage binding differs")
        transaction_id = package_stage.get("transaction_id", "")
        observed = self._validate_stage_authority(stage, transaction_id)
        retained = self._stages.get(transaction_id)
        if retained is not None and retained != observed:
            raise BuildError("production native staged authority differs")
        if self._operation("validate_stage")(
            observed, source, package_stage,
        ) is not True:
            raise BuildError("production native staged authority differs")
        self._stages[transaction_id] = observed
        return True

    def commit(
        self, home: Path, stage: dict[str, Any], source: dict[str, Any],
        package_receipt: dict[str, Any],
    ) -> dict[str, Any]:
        self._bind_home_source(home, source)
        if type(package_receipt) is not dict:
            raise BuildError("production native package receipt differs")
        transaction_id = stage.get("transaction_id", "") if type(stage) is dict else ""
        observed = self._validate_stage_authority(stage, transaction_id)
        if self._stages.get(transaction_id) != observed:
            raise BuildError("production native commit stage differs")
        result = self._operation("commit")(
            home, observed, source, package_receipt,
        )
        if type(result) is not dict:
            raise BuildError("production native commit returned no authority")
        return result

    def validate_installed(
        self, home: Path, package_receipt: dict[str, Any],
    ) -> dict[str, Any]:
        if home.absolute() != self._home or type(package_receipt) is not dict:
            raise BuildError("production native installed binding differs")
        result = self._operation("validate_installed")(home, package_receipt)
        if type(result) is not dict:
            raise BuildError("production native validator returned no authority")
        return result

    def rollback(
        self, home: Path, receipts: dict[str, Any], prior: dict[str, Any],
    ) -> bool:
        if (
            home.absolute() != self._home or type(receipts) is not dict
            or type(prior) is not dict
        ):
            raise BuildError("production native rollback binding differs")
        if self._operation("rollback")(home, receipts, prior) is not True:
            raise BuildError("production native rollback was incomplete")
        return True

    def cleanup(
        self, home: Path, package_stage: dict[str, Any] | None,
        native_stage: dict[str, Any] | None,
    ) -> bool:
        if home.absolute() != self._home:
            raise BuildError("production native cleanup account differs")
        if self._operation("cleanup")(
            home, package_stage, native_stage,
        ) is not True:
            raise BuildError("production native private-stage cleanup was incomplete")
        return True

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        errors: list[BaseException] = []
        try:
            if self._authority.close() is not True:
                errors.append(BuildError(
                    "production native acquisition custody did not close"
                ))
        except BaseException as exc:
            errors.append(exc)
        try:
            if self._source_roster.close() is not True:
                errors.append(BuildError(
                    "production native source custody did not close"
                ))
        except BaseException as exc:
            errors.append(exc)
        self._stages.clear()
        if errors:
            raise BuildError(
                "production native transaction custody did not close"
            ) from errors[0]
        return True


class _PrivateProductionOperation4ExecutionRoot:
    """Own one descriptor-retained operation-4 preparation transaction.

    The root is created beside the already-private package snapshot and is
    never published.  Every callback needed to acquire all eleven role rows is
    admitted before the directory is created, so an incomplete production
    roster cannot perform compilation, network setup, or signer effects.
    """

    __slots__ = (
        "_root", "_root_fd", "_compiled", "_fixed_preparation",
        "_fixed_records", "_backend_roles", "_evm_roles", "_operation4",
        "_closed",
    )
    _PLAMEN_PRIVATE_OPERATION4_EXECUTION_ROOT_V1 = True

    _CALLBACKS = (
        "compile_release_artifacts",
        "seal_fixed_role_source_projections",
        "prepare_production_fixed_role_inputs",
        "derive_production_operation4_policy_rows",
        "acquire_production_evm_static_upstreams",
        "issue_production_native_evm_static_roles",
        "acquire_production_backend_inputs",
        "issue_production_native_backend_roles",
        "compose_production_operation4_inputs",
    )

    def __init__(self) -> None:
        self._root: Path | None = None
        self._root_fd = -1
        self._compiled: dict[str, dict[str, Any]] = {}
        self._fixed_preparation: Any = None
        self._fixed_records: tuple[Any, ...] = ()
        self._backend_roles: Any = None
        self._evm_roles: Any = None
        self._operation4: MappingProxyType | None = None
        self._closed = False

    @staticmethod
    def _mkdir_private(parent: Path) -> tuple[Path, int]:
        parent_fd = -1
        try:
            parent_fd = _open_directory_nofollow(parent)
            parent_info = os.fstat(parent_fd)
            if (
                parent_info.st_uid != os.geteuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700
            ):
                raise BuildError("operation-4 parent workspace is not private")
            for _attempt in range(16):
                name = ".plamen-operation4-" + secrets.token_hex(16)
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                os.fsync(parent_fd)
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
                path = parent / name
                if not _same_stat(
                    os.fstat(descriptor),
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False),
                ):
                    os.close(descriptor)
                    raise BuildError("operation-4 private root rejoin differs")
                return path, descriptor
            raise BuildError("operation-4 private root allocation failed")
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)

    @staticmethod
    def _mkdir_child(root_fd: int, name: str) -> tuple[Path, int]:
        if _SAFE_COMPONENT.fullmatch(name) is None:
            raise BuildError("operation-4 private child name differs")
        os.mkdir(name, mode=0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise BuildError("operation-4 private child authority differs")
        return Path(name), descriptor

    @classmethod
    def acquire(
        cls, *, source_freeze: dict[str, Any],
        source_roster: _RetainedFrozenSourceRoster,
        package_snapshot: dict[str, Any],
        builder_callbacks: MappingProxyType,
    ) -> "_PrivateProductionOperation4ExecutionRoot":
        if (
            type(builder_callbacks).__name__ != "mappingproxy"
            or type(source_freeze) is not dict
            or type(package_snapshot) is not dict
            or getattr(
                source_roster, "_PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1",
                None,
            ) is not True
        ):
            raise BuildError("operation-4 execution-root inputs differ")
        missing = tuple(
            name for name in cls._CALLBACKS
            if not callable(builder_callbacks.get(name))
        )
        if missing:
            raise BuildError(
                "PRODUCTION_NATIVE_OPERATION4_INPUT_PRODUCERS_UNAVAILABLE:"
                + ",".join(missing)
            )
        snapshot_root_raw = package_snapshot.get("root")
        if type(snapshot_root_raw) is not str:
            raise BuildError("operation-4 package snapshot root differs")
        snapshot_root = _canonical_absolute_path(
            Path(snapshot_root_raw), "operation-4 package snapshot root",
        )
        if snapshot_root.name != "package-snapshot":
            raise BuildError("operation-4 package snapshot root differs")
        owner = cls()
        child_fds: list[int] = []
        try:
            owner._root, owner._root_fd = cls._mkdir_private(
                snapshot_root.parent,
            )
            children: dict[str, tuple[Path, int]] = {}
            for name in ("pre-policy", "policy", "generation", "stores"):
                relative, descriptor = cls._mkdir_child(owner._root_fd, name)
                child_fds.append(descriptor)
                children[name] = (owner._root / relative, descriptor)

            compile_release = builder_callbacks["compile_release_artifacts"]
            preliminary_kinds = tuple(
                row["kind"] for row in PRODUCTION_DARWIN_LINK_ROSTER
                if row["kind"] not in PRODUCTION_OPERATION4_POLICY_CONSUMERS
            ) + ("retained-generation-stage-helper",)
            preliminary = compile_release(
                children["pre-policy"][0], children["pre-policy"][1],
                source_freeze, operation4_policy_rows=None,
                artifact_kinds=preliminary_kinds,
            )
            if type(preliminary) is not dict or set(preliminary) != set(
                preliminary_kinds
            ):
                raise BuildError("operation-4 preliminary compilation differs")
            owner._compiled.update(preliminary)

            fixed_module = _load_frozen_source_module(
                "_plamen_frozen_native_fixed_role_operation4",
                "native_fixed_role_acquisition", source_freeze,
            )
            store_type = getattr(fixed_module, "RetainedPrivateStoreFactory", None)
            if not callable(store_type):
                raise BuildError("operation-4 private-store factory is absent")
            private_store = store_type(children["stores"][1])
            seal = builder_callbacks["seal_fixed_role_source_projections"]
            sealed = seal(
                source_freeze=source_freeze, source_roster=source_roster,
                package_snapshot=package_snapshot,
                compiled_artifacts=owner._compiled,
                private_store=private_store,
            )
            if type(sealed) is not MappingProxyType or set(sealed) != {
                "plamen_guest", "plamen_package",
            }:
                raise BuildError("operation-4 fixed source projection differs")

            prepare_fixed = builder_callbacks[
                "prepare_production_fixed_role_inputs"
            ]
            owner._fixed_preparation = prepare_fixed(
                source_freeze=source_freeze, source_roster=source_roster,
                private_store=private_store, frozen_module=fixed_module,
            )
            materialized = getattr(
                owner._fixed_preparation, "materialized_inputs", None,
            )
            issue_fixed = getattr(owner._fixed_preparation, "issue", None)
            if not callable(materialized) or not callable(issue_fixed):
                raise BuildError("operation-4 fixed-role preparation differs")
            fixed_inputs = materialized()
            policy_rows = builder_callbacks[
                "derive_production_operation4_policy_rows"
            ](
                source_freeze=source_freeze, source_roster=source_roster,
                fixed_materialized_inputs=fixed_inputs,
            )
            if type(policy_rows) is not tuple or len(policy_rows) != 11:
                raise BuildError("operation-4 compile policy rows differ")
            policy_compile = compile_release(
                children["policy"][0], children["policy"][1], source_freeze,
                operation4_policy_rows=policy_rows,
                artifact_kinds=("retained-source-bootstrap-coordinator",),
            )
            if type(policy_compile) is not dict or set(policy_compile) != {
                "retained-source-bootstrap-coordinator",
            }:
                raise BuildError("operation-4 policy compilation differs")
            owner._compiled.update(policy_compile)

            coordinator = owner._compiled[
                "retained-source-bootstrap-coordinator"
            ]
            owner._fixed_records = issue_fixed(
                coordinator=coordinator,
                staged_generation_root_fd=children["generation"][1],
                materialized_inputs=fixed_inputs,
            )
            if type(owner._fixed_records) is not tuple or len(
                owner._fixed_records
            ) != 7:
                raise BuildError("operation-4 fixed-role issue differs")

            upstreams = builder_callbacks[
                "acquire_production_evm_static_upstreams"
            ](
                source_freeze=source_freeze, source_roster=source_roster,
                private_store=private_store, builder_callbacks=builder_callbacks,
            )
            owner._evm_roles = builder_callbacks[
                "issue_production_native_evm_static_roles"
            ](
                source_freeze=source_freeze, source_roster=source_roster,
                compiled_artifacts=owner._compiled,
                staged_generation_root_fd=children["generation"][1],
                upstream_authority=upstreams,
                builder_callbacks=builder_callbacks,
            )
            backend_inputs = builder_callbacks[
                "acquire_production_backend_inputs"
            ](
                source_freeze=source_freeze, source_roster=source_roster,
                private_store=private_store, builder_callbacks=builder_callbacks,
            )
            owner._backend_roles = builder_callbacks[
                "issue_production_native_backend_roles"
            ](
                source_freeze=source_freeze, source_roster=source_roster,
                compiled_artifacts=owner._compiled,
                private_store=private_store, input_authority=backend_inputs,
                builder_callbacks=builder_callbacks,
            )
            owner._operation4 = builder_callbacks[
                "compose_production_operation4_inputs"
            ](
                fixed_role_records=owner._fixed_records,
                backend_authority=owner._backend_roles,
                evm_static_authority=owner._evm_roles,
            )
            if (
                type(owner._operation4) is not MappingProxyType
                or set(owner._operation4) != {"policy_rows", "role_fds"}
                or len(owner._operation4["policy_rows"]) != 11
                or len(owner._operation4["role_fds"]) != 11
            ):
                raise BuildError("operation-4 retained fold differs")
            return owner
        except BaseException:
            owner.close()
            raise
        finally:
            for descriptor in child_fds:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def operation4_inputs(self) -> MappingProxyType:
        if self._closed or self._operation4 is None:
            raise BuildError("operation-4 execution authority is unavailable")
        return self._operation4

    def compiled_artifacts(self) -> MappingProxyType:
        if self._closed or not self._compiled:
            raise BuildError("operation-4 compiled authority is unavailable")
        return MappingProxyType(dict(self._compiled))

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        failures: list[BaseException] = []
        for authority in (
            self._backend_roles, self._evm_roles, self._fixed_preparation,
        ):
            close = getattr(authority, "close", None)
            if callable(close):
                try:
                    result = close()
                    if result not in {None, True}:
                        failures.append(BuildError(
                            "operation-4 retained custody did not close"
                        ))
                except BaseException as exc:
                    failures.append(exc)
        for value in self._fixed_records:
            for field in (
                "payload_fd", "producer_receipt_fd", "source_manifest_fd",
            ):
                descriptor = getattr(value, field, -1)
                if type(descriptor) is int and descriptor >= 3:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
        for artifact in self._compiled.values():
            descriptor = artifact.get("fd", -1) if type(artifact) is dict else -1
            if type(descriptor) is int and descriptor >= 3:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self._compiled = {}
        self._fixed_records = ()
        self._backend_roles = self._evm_roles = self._fixed_preparation = None
        self._operation4 = None
        if self._root_fd >= 0:
            try:
                if self._root is None or not _same_stat(
                    os.fstat(self._root_fd),
                    os.stat(self._root, follow_symlinks=False),
                ):
                    raise BuildError("operation-4 private root changed")
                shutil.rmtree(self._root)
            except BaseException as exc:
                failures.append(exc)
            finally:
                os.close(self._root_fd)
                self._root_fd = -1
        self._root = None
        if failures:
            raise BuildError("operation-4 private-root cleanup failed") from failures[0]
        return True


class _ProductionNativeAcquisitionWithOperation4:
    """Retain operation-4 custody for the full native stage delegate."""

    __slots__ = ("_operation4", "_delegate", "_closed")
    _PLAMEN_PRODUCTION_NATIVE_ACQUISITION_V1 = True

    def __init__(self, operation4: Any, delegate: Any) -> None:
        required = (
            "stage", "validate_stage", "commit", "validate_installed",
            "rollback", "cleanup", "close",
        )
        if (
            getattr(
                operation4, "_PLAMEN_PRIVATE_OPERATION4_EXECUTION_ROOT_V1",
                None,
            ) is not True
            or getattr(
                delegate, "_PLAMEN_PRODUCTION_NATIVE_STAGE_AUTHORITY_V1", None,
            ) is not True
            or any(not callable(getattr(delegate, name, None)) for name in required)
        ):
            raise BuildError("production native stage authority differs")
        self._operation4 = operation4
        self._delegate = delegate
        self._closed = False

    def _call(self, name: str, *args: Any) -> Any:
        if self._closed:
            raise BuildError("production native acquisition authority is closed")
        return getattr(self._delegate, name)(*args)

    def stage(self, *args: Any) -> Any:
        return self._call("stage", *args)

    def validate_stage(self, *args: Any) -> Any:
        return self._call("validate_stage", *args)

    def commit(self, *args: Any) -> Any:
        return self._call("commit", *args)

    def validate_installed(self, *args: Any) -> Any:
        return self._call("validate_installed", *args)

    def rollback(self, *args: Any) -> Any:
        return self._call("rollback", *args)

    def cleanup(self, *args: Any) -> Any:
        return self._call("cleanup", *args)

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        failures: list[BaseException] = []
        for value in (self._delegate, self._operation4):
            try:
                if value.close() is not True:
                    failures.append(BuildError(
                        "production native acquisition custody did not close"
                    ))
            except BaseException as exc:
                failures.append(exc)
        if failures:
            raise BuildError(
                "production native acquisition custody did not close"
            ) from failures[0]
        return True


def _prepare_production_fixed_role_inputs(
    *, source_freeze: dict[str, Any],
    source_roster: _RetainedFrozenSourceRoster, private_store: Any,
    frozen_module: ModuleType,
) -> Any:
    """Bind materialization and native issue to one frozen module identity."""

    materialize = getattr(
        frozen_module, "acquire_production_fixed_role_materialized_inputs", None,
    )
    runner = getattr(frozen_module, "run_native_fixed_role_issue_cli", None)
    if not callable(materialize) or not callable(runner):
        raise BuildError("frozen fixed-role producer is incomplete")
    try:
        authority = materialize(
            source_authority=source_roster, private_store=private_store,
        )
    except BaseException as exc:
        raise BuildError(
            "production fixed-role materialization failed: "
            + type(exc).__name__
        ) from None

    class Preparation:
        __slots__ = ("_authority", "_closed")

        def __init__(self, value: Any) -> None:
            self._authority = value
            self._closed = False

        def materialized_inputs(self) -> tuple[Any, ...]:
            if self._closed:
                raise BuildError("production fixed-role preparation is closed")
            return self._authority.materialized_inputs()

        def issue(
            self, *, coordinator: dict[str, Any],
            staged_generation_root_fd: int,
            materialized_inputs: tuple[Any, ...],
        ) -> tuple[Any, ...]:
            if self._closed or type(coordinator) is not dict:
                raise BuildError("production fixed-role issue authority differs")
            try:
                return runner(
                    executable_fd=coordinator["fd"],
                    executable_path=(
                        str(coordinator["path"])
                        if sys.platform == "darwin" else None
                    ),
                    staged_generation_root_fd=staged_generation_root_fd,
                    inputs=materialized_inputs,
                )
            except BaseException as exc:
                raise BuildError(
                    "production fixed-role issue failed: " + type(exc).__name__
                ) from None

        def close(self) -> bool:
            if self._closed:
                return True
            self._closed = True
            result = self._authority.close()
            if result not in {None, True}:
                raise BuildError("production fixed-role custody did not close")
            return True

    return Preparation(authority)


def _acquire_production_native_authority(**values: Any) -> Any:
    """Assemble operation 4 only behind complete opaque producer authority."""

    required = {
        "home", "source_freeze", "source_authority", "source_roster",
        "package_snapshot", "builder_callbacks",
    }
    if set(values) != required:
        raise BuildError("production native acquisition inputs differ")
    callbacks = values["builder_callbacks"]
    if type(callbacks).__name__ != "mappingproxy":
        raise BuildError("production native acquisition callbacks differ")
    missing = tuple(
        name for name in (
            "acquire_production_backend_inputs",
            "bind_production_native_stage_authority",
        ) if not callable(callbacks.get(name))
    )
    if missing:
        raise BuildError(
            "PRODUCTION_NATIVE_RETAINED_ACQUISITION_UNAVAILABLE:"
            + ",".join(missing)
        )
    operation4 = _PrivateProductionOperation4ExecutionRoot.acquire(
        source_freeze=values["source_freeze"],
        source_roster=values["source_roster"],
        package_snapshot=values["package_snapshot"],
        builder_callbacks=callbacks,
    )
    try:
        delegate = callbacks["bind_production_native_stage_authority"](
            home=values["home"], source_freeze=values["source_freeze"],
            source_authority=values["source_authority"],
            source_roster=values["source_roster"], operation4=operation4,
            builder_callbacks=callbacks,
        )
        return _ProductionNativeAcquisitionWithOperation4(operation4, delegate)
    except BaseException:
        operation4.close()
        raise


def _prepare_production_native_transaction(
    *, home: Path, source_freeze: dict[str, Any],
    source_authority: dict[str, Any], package_snapshot: dict[str, Any] | None = None,
    builder_callbacks: MappingProxyType,
) -> _RetainedProductionNativeTransaction:
    """Acquire and bind one descriptor-retained native install transaction."""

    if (
        type(builder_callbacks).__name__ != "mappingproxy"
        or type(source_authority) is not dict
        or type(source_freeze) is not dict
    ):
        raise BuildError("production native preparation authority differs")
    provider = builder_callbacks.get("acquire_production_native_authority")
    if not callable(provider):
        raise BuildError("production native acquisition provider is absent")
    if provider is _acquire_production_native_authority and type(
        package_snapshot
    ) is not dict:
        raise BuildError("production native package snapshot is absent")
    source_roster = _retain_exact_frozen_source_roster(source_freeze)
    authority: Any = None
    try:
        authority = provider(
            home=home, source_freeze=source_freeze,
            source_authority=source_authority,
            source_roster=source_roster,
            package_snapshot=package_snapshot,
            builder_callbacks=builder_callbacks,
        )
        return _RetainedProductionNativeTransaction(
            home=home.absolute(), source=source_authority,
            authority=authority, source_roster=source_roster,
        )
    except BaseException:
        if authority is not None:
            close = getattr(authority, "close", None)
            if callable(close):
                close()
        source_roster.close()
        raise


def _production_native_session(
    production_context: object, operation: str,
) -> tuple[Any, Any]:
    if (
        type(production_context) is not dict
        or set(production_context) != {
            "source_freeze", "source_authority", "builder_callbacks",
            "native_transaction",
        }
        or type(production_context.get("builder_callbacks")).__name__
        != "mappingproxy"
    ):
        raise BuildError("production native transaction context differs")
    session = production_context["native_transaction"]
    marker = getattr(session, "_PLAMEN_RETAINED_NATIVE_TRANSACTION_V1", None)
    callback = getattr(session, operation, None)
    if marker is not True or not callable(callback):
        raise BuildError("production native transaction authority differs")
    return session, callback


def _production_native_stage(
    home: Path, transaction_root: Path, source: dict[str, Any],
    package_stage: dict[str, Any], *, production_context: dict[str, Any],
) -> dict[str, Any]:
    _session, operation = _production_native_session(production_context, "stage")
    result = operation(home, transaction_root, source, package_stage)
    if type(result) is not dict:
        raise BuildError("production native stage returned no authority")
    return result


def _production_native_stage_validate(
    stage: dict[str, Any], source: dict[str, Any],
    package_stage: dict[str, Any], *, production_context: dict[str, Any],
) -> bool:
    _session, operation = _production_native_session(
        production_context, "validate_stage",
    )
    if operation(stage, source, package_stage) is not True:
        raise BuildError("production native staged authority differs")
    return True


def _production_native_commit(
    home: Path, stage: dict[str, Any], source: dict[str, Any],
    package_receipt: dict[str, Any], *,
    production_context: dict[str, Any],
) -> dict[str, Any]:
    _session, operation = _production_native_session(production_context, "commit")
    result = operation(home, stage, source, package_receipt)
    if type(result) is not dict:
        raise BuildError("production native commit returned no authority")
    return result


def _production_native_validate(
    home: Path, package_receipt: dict[str, Any], *,
    production_context: dict[str, Any],
) -> dict[str, Any]:
    _session, operation = _production_native_session(
        production_context, "validate_installed",
    )
    result = operation(home, package_receipt)
    if type(result) is not dict:
        raise BuildError("production native validator returned no authority")
    return result


def _production_native_rollback(
    home: Path, receipts: dict[str, Any], prior: dict[str, Any], *,
    production_context: dict[str, Any],
) -> bool:
    _session, operation = _production_native_session(
        production_context, "rollback",
    )
    if operation(home, receipts, prior) is not True:
        raise BuildError("production native rollback was incomplete")
    return True


def _production_native_cleanup(
    home: Path, package_stage: dict[str, Any] | None,
    native_stage: dict[str, Any] | None, *,
    production_context: dict[str, Any],
) -> bool:
    _session, operation = _production_native_session(production_context, "cleanup")
    if operation(home, package_stage, native_stage) is not True:
        raise BuildError("production native private-stage cleanup was incomplete")
    return True


class _ProductionColdInstallEffectsLease:
    """Keep retained native transaction custody scoped to one coordinator run."""

    __slots__ = ("_effects", "_native_transaction", "_closed")

    def __init__(self, effects: Any, native_transaction: Any) -> None:
        self._effects = effects
        self._native_transaction = native_transaction
        self._closed = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._effects, name)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = getattr(self._native_transaction, "close", None)
        if not callable(close) or close() is not True:
            raise BuildError("production native transaction custody did not close")


def _production_native_builder_callbacks() -> MappingProxyType:
    """Expose the narrow retained builder surface to the effects adapter.

    The adapter receives operations which create or validate authorities, not
    output path strings.  In particular, compile and interpreter operations
    return still-open descriptors whose custody is transferred to the adapter.
    """

    return MappingProxyType({
        "compile_release_artifacts": _compile_darwin_source_release_artifacts,
        "load_frozen_source_module": _load_frozen_source_module,
        "validate_runtime_source_projection": (
            _validate_frozen_runtime_source_projection
        ),
        "open_native_install_layout": _open_native_install_layout,
        "normalize_runtime_bindings": _normalize_native_runtime_bindings,
        "retain_cpython_312": _retain_production_cpython_312,
        "stage_backend_profiles": stage_darwin_backend_profiles_v2,
        "bind_retained_backend_generation": (
            _bind_retained_backend_generation
        ),
        "render_runtime_manifest": render_runtime_package_manifest_v2,
        "validate_runtime_manifest": validate_runtime_package_manifest_v2,
        "freeze_materialized_tree": _freeze_materialized_tree,
        "run_generation_stage": _run_native_generation_stage_cli,
        "run_native_prepare_publish": _run_native_prepare_publish_cli,
        "run_native_publish": _run_native_install_coordinator_cli,
        "run_native_installed_receipt": _run_native_installed_receipt_cli,
        "run_native_evm_static_acquisition": (
            _run_native_evm_static_acquisition_cli
        ),
        "fetch_exact_setup_upstream": _fetch_exact_setup_upstream,
        "acquire_production_evm_static_upstreams": (
            _acquire_production_evm_static_upstreams
        ),
        "issue_production_native_evm_static_roles": (
            _issue_production_native_evm_static_roles
        ),
        "run_native_fixed_role_acquisition": (
            _run_native_fixed_role_acquisition_cli
        ),
        "run_native_source_bootstrap_issue": (
            _run_native_source_bootstrap_issue_cli
        ),
        "run_native_backend_receipt_signer": (
            _run_native_backend_receipt_signer_cli
        ),
        "issue_production_native_backend_roles": (
            _issue_production_native_backend_roles
        ),
        "compose_production_operation4_inputs": (
            _compose_production_operation4_inputs
        ),
        "derive_production_operation4_policy_rows": (
            _derive_production_operation4_policy_rows
        ),
        "observe_darwin_code_identity": _darwin_ad_hoc_code_identity,
        "render_operation4_fixed_policy_source": (
            _render_operation4_fixed_policy_source
        ),
        "seal_fixed_role_source_projections": (
            _seal_production_fixed_role_source_projections
        ),
        "prepare_production_fixed_role_inputs": (
            _prepare_production_fixed_role_inputs
        ),
        "acquire_production_native_authority": (
            _acquire_production_native_authority
        ),
        # The six outer effects are deliberately present as one closed
        # protocol.  They can only be reached after
        # ``prepare_production_native_transaction`` has returned an opaque,
        # process-local authority.  The source build currently has no honest
        # retained acquisition producer for that authority, so the typed
        # provider above fails before the cold-install coordinator creates its
        # journal or mutates HOME.
        "prepare_production_native_transaction": (
            _prepare_production_native_transaction
        ),
        "production_native_stage": _production_native_stage,
        "production_native_stage_validate": (
            _production_native_stage_validate
        ),
        "production_native_commit": _production_native_commit,
        "production_native_validate": _production_native_validate,
        "production_native_rollback": _production_native_rollback,
        "production_native_cleanup": _production_native_cleanup,
    })


def _load_frozen_cold_install_stack(
    source_freeze: dict[str, Any],
) -> dict[str, Any]:
    """Load the reviewed install graph from already-replayed frozen bytes.

    The coordinator imports its publication helper and the effects adapter
    imports both.  Populate those dependency names only while executing the
    retained bytes, then restore the caller's module table.  No component is
    reopened through import path discovery and the production builder is not
    imported recursively.
    """

    names = (
        "posix_native_install_publication",
        "posix_native_install_transaction",
        "posix_native_install_effects",
    )
    previous = {name: sys.modules.get(name) for name in names}
    try:
        publication = _load_frozen_source_module(
            names[0], "cold_install_publication", source_freeze,
        )
        sys.modules[names[0]] = publication
        transaction = _load_frozen_source_module(
            names[1], "cold_install_transaction", source_freeze,
        )
        sys.modules[names[1]] = transaction
        effects = _load_frozen_source_module(
            names[2], "cold_install_effects", source_freeze,
        )
        sys.modules[names[2]] = effects
        package = _load_frozen_source_module(
            "_plamen_frozen_package_front", "package_front", source_freeze,
        )
    finally:
        for name in reversed(names):
            value = previous[name]
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
    constructor = getattr(effects, "DarwinColdInstallEffects", None)
    execute = getattr(transaction, "execute_cold_install_transaction", None)
    source_authority = getattr(
        transaction, "source_authority_from_validated_freeze", None,
    )
    package_commit = getattr(package, "_install_codex_package_transaction", None)
    package_rollback = getattr(
        package, "_rollback_committed_codex_package_transaction", None,
    )
    if (
        getattr(package, "_FROZEN_PACKAGE_FRONT_STDLIB_ONLY", None) is not True
        or any(not callable(value) for value in (
        constructor, execute, source_authority, package_commit,
        package_rollback,
        ))
    ):
        raise BuildError("frozen cold-install stack is incomplete")
    return {
        "publication": publication, "transaction": transaction,
        "effects": effects, "package": package,
    }


def _create_production_cold_install_effects(
    *, home: Path, source_freeze: dict[str, Any],
    source_authority: dict[str, Any], package_snapshot: dict[str, Any],
    builder_callbacks: MappingProxyType, cold_stack: dict[str, Any],
) -> Any:
    """Bind the frozen package transaction to retained native effects.

    The frozen package front owns its package commit/inverse.  Native stage,
    validation, commit, rollback and cleanup remain builder operations and
    must all be present before the effects object is constructed.  Missing
    callbacks therefore fail before the outer coordinator creates its durable
    journal or mutates the account.
    """

    if (
        type(cold_stack) is not dict
        or set(cold_stack) != {
            "publication", "transaction", "effects", "package",
        }
        or type(builder_callbacks).__name__ != "mappingproxy"
        or type(source_freeze) is not dict
        or type(source_authority) is not dict
        or type(package_snapshot) is not dict
    ):
        raise BuildError("production cold-install authority is malformed")
    package = cold_stack["package"]
    constructor = getattr(
        cold_stack["effects"], "DarwinColdInstallEffects", None,
    )
    package_commit_operation = getattr(
        package, "_install_codex_package_transaction", None,
    )
    package_rollback_operation = getattr(
        package, "_rollback_committed_codex_package_transaction", None,
    )
    required_native = {
        name: builder_callbacks.get(name) for name in (
            "production_native_stage",
            "production_native_stage_validate",
            "production_native_commit",
            "production_native_validate",
            "production_native_rollback",
            "production_native_cleanup",
        )
    }
    prepare_native = builder_callbacks.get(
        "prepare_production_native_transaction"
    )
    if (
        not callable(constructor)
        or getattr(package, "_FROZEN_PACKAGE_FRONT_STDLIB_ONLY", None)
        is not True
        or not callable(package_commit_operation)
        or not callable(package_rollback_operation)
        or not callable(prepare_native)
        or any(not callable(value) for value in required_native.values())
    ):
        raise BuildError("production cold-install effect roster is incomplete")

    # This admission happens before DarwinColdInstallEffects is constructed.
    # Consequently an unavailable or malformed retained acquisition bundle
    # cannot cause the outer coordinator to create its journal or mutate HOME.
    native_transaction = prepare_native(
        home=home, source_freeze=source_freeze,
        source_authority=source_authority,
        package_snapshot=package_snapshot,
        builder_callbacks=builder_callbacks,
    )
    if getattr(
        native_transaction, "_PLAMEN_RETAINED_NATIVE_TRANSACTION_V1", None,
    ) is not True or not callable(getattr(native_transaction, "close", None)):
        raise BuildError("production native transaction authority differs")

    def package_commit(
        account: Path, durable_source: Path, _stage: dict[str, Any],
        _source: dict[str, Any],
    ) -> dict[str, Any]:
        if account.absolute() != home or not durable_source.is_absolute():
            raise BuildError("production package commit authority differs")
        result = package_commit_operation(
            source_root=durable_source,
            plamen_root=home / ".plamen",
            codex_home=home / ".codex",
        )
        if type(result) is not dict:
            raise BuildError("production package commit returned no receipt")
        return result

    def package_validate(account: Path) -> dict[str, Any]:
        if account.absolute() != home:
            raise BuildError("production package validation account differs")
        return validate_codex_committed_package_v2(home)

    def package_rollback(
        account: Path, receipt: dict[str, Any], prior: dict[str, Any],
    ) -> bool:
        if account.absolute() != home:
            raise BuildError("production package rollback account differs")
        result = package_rollback_operation(
            receipt, prior, codex_home=home / ".codex",
            plamen_root=home / ".plamen",
        )
        if result is not True:
            raise BuildError("production package rollback was incomplete")
        return True

    context = {
        "source_freeze": source_freeze,
        "source_authority": source_authority,
        "builder_callbacks": builder_callbacks,
        "native_transaction": native_transaction,
    }

    def bind(name: str) -> Any:
        operation = required_native[name]

        def invoked(*args: Any) -> Any:
            return operation(*args, production_context=context)

        return invoked

    try:
        effects = constructor(
            home=home, package_snapshot=package_snapshot,
            package_commit=package_commit, package_validate=package_validate,
            package_rollback=package_rollback,
            native_stage=bind("production_native_stage"),
            native_stage_validate=bind("production_native_stage_validate"),
            native_commit=bind("production_native_commit"),
            native_validate=bind("production_native_validate"),
            native_rollback=bind("production_native_rollback"),
            cleanup=bind("production_native_cleanup"),
        )
    except BaseException:
        closed = native_transaction.close()
        if closed is not True:
            raise BuildError(
                "production native transaction custody did not close"
            ) from None
        raise
    return _ProductionColdInstallEffectsLease(effects, native_transaction)


def _validate_source_install_readiness(readiness: object) -> dict[str, Any]:
    if (
        type(readiness) is not dict
        or readiness.get("schema")
        != "plamen.native-supervisor.production-readiness.v2"
        or readiness.get("authority")
        != "DIAGNOSTIC_ONLY_LOADED_PYTHON_NO_BUILD_AUTHORITY"
        or type(readiness.get("production_build_allowed")) is not bool
        or type(readiness.get("blockers")) is not list
        or type(readiness.get("transaction_admission_blockers")) is not list
        or any(type(code) is not str or not code for code in readiness["blockers"])
        or readiness["blockers"] != sorted(set(readiness["blockers"]))
        or readiness["transaction_admission_blockers"]
        != sorted(set(readiness["blockers"]) - PRODUCTION_COLD_INSTALL_OUTPUT_BLOCKERS)
        or readiness["production_build_allowed"]
        is not (not readiness["transaction_admission_blockers"])
        or not isinstance(readiness.get("observation_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", readiness["observation_sha256"])
        is None
    ):
        raise BuildError("source install readiness observation is malformed")
    unsigned = dict(readiness)
    digest = unsigned.pop("observation_sha256")
    if not secrets.compare_digest(
        hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest(), digest,
    ):
        raise BuildError("source install readiness observation digest differs")
    if readiness["transaction_admission_blockers"]:
        raise BuildError(
            "source install transaction is not complete; prerequisite blockers="
            + ",".join(readiness["transaction_admission_blockers"])
        )
    return dict(readiness)


def _execute_native_source_install_transaction(
    readiness: dict[str, Any], *, home: Path | None = None,
    coordinator_module: Any = None, effects_factory: Any = None,
    package_snapshot_factory: Any = None,
) -> dict[str, Any]:
    """Enter the production transaction only after every authority is green.

    This is the single source dispatcher-to-builder call seam.  It performs no
    filesystem mutation while any prerequisite is absent.  The retained
    compile/sign/stage/coordinator implementation must replace the final hard
    stop as one indivisible transaction; Python observations are never
    promoted into native installation authority here.
    """

    _validate_source_install_readiness(readiness)
    if readiness.get("platform") == "linux":
        # Linux policy is now selected and diagnosed independently, but loaded
        # Python must never substitute for the not-yet-frozen native Linux
        # effects/coordinator authority.
        raise BuildError("LINUX_NATIVE_INSTALL_EFFECTS_UNAVAILABLE")
    # This replay is deliberately after readiness validation and before the
    # effects object or coordinator is allowed to create a control directory.
    # It validates the semantically frozen runtime projection as well as every
    # fixed source member.
    source_freeze = _load_exact_production_source_freeze()
    cold_stack: dict[str, Any] | None = None
    if coordinator_module is None or effects_factory is None:
        if coordinator_module is not None or effects_factory is not None:
            raise BuildError(
                "source install coordinator/effects selection is partial"
            )
        cold_stack = _load_frozen_cold_install_stack(source_freeze)
        coordinator_module = cold_stack["transaction"]

        def effects_factory(**values: Any) -> Any:
            return _create_production_cold_install_effects(
                **values, cold_stack=cold_stack,
            )
    source_authority_factory = getattr(
        coordinator_module, "source_authority_from_validated_freeze", None,
    )
    execute = getattr(
        coordinator_module, "execute_cold_install_transaction", None,
    )
    if not callable(source_authority_factory) or not callable(execute):
        raise BuildError("cold-install coordinator interface is malformed")
    account = _canonical_absolute_path(
        home or Path(pwd.getpwuid(os.getuid()).pw_dir),
        "source install account home",
    )
    source_authority = source_authority_factory(
        REPOSITORY_ROOT, source_freeze,
    )
    snapshot_factory = (
        _materialize_frozen_package_snapshot
        if package_snapshot_factory is None else package_snapshot_factory
    )
    if not callable(snapshot_factory):
        raise BuildError("package snapshot factory is unavailable")
    with tempfile.TemporaryDirectory(
        prefix="plamen-native-source-install-",
    ) as temporary:
        workspace = Path(temporary)
        package_snapshot = snapshot_factory(
            workspace, account, source_freeze,
        )
        effects = effects_factory(
            home=account,
            source_freeze=source_freeze,
            source_authority=source_authority,
            package_snapshot=package_snapshot,
            builder_callbacks=_production_native_builder_callbacks(),
        )
        try:
            return execute(
                home=account, source_authority=source_authority,
                effects=effects,
            )
        finally:
            if isinstance(effects, _ProductionColdInstallEffectsLease):
                active = sys.exception()
                try:
                    effects.close()
                except BaseException as cleanup_error:
                    if active is None:
                        raise
                    active.add_note(
                        "retained native transaction cleanup also failed: "
                        f"{type(cleanup_error).__name__}:{cleanup_error}"
                    )


def install_codex_from_source() -> dict[str, Any]:
    """Run the fixed source-install entrypoint through its sole transaction seam.

    The public dispatcher supplies this exact closed environment and invokes
    this file with CPython 3.12.  Keeping the entrypoint here makes the handoff
    stable while the remaining multi-artifact transaction is implemented; it
    must never turn a readiness observation into installation authority.
    """

    expected_environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
    }
    observed_environment = dict(os.environ)
    injected = observed_environment.pop("__CF_USER_TEXT_ENCODING", None)
    expected_injected = f"0x{os.getuid():X}:0x0:0x0"
    if (
        observed_environment != expected_environment
        or injected not in (None, expected_injected)
    ):
        raise BuildError("source install requires the exact closed environment")
    platform_key = _production_host_platform_key()
    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:2] != PRODUCTION_CPYTHON_ABI
    ):
        raise BuildError(
            "SOURCE_INSTALL_CPYTHON_ABI_UNSUPPORTED: source install requires "
            "exact CPython 3.12"
        )
    if platform_key not in {"darwin-arm64", "linux-x86_64", "linux-arm64"}:
        raise BuildError("NATIVE_RELEASE_SLICE_UNSUPPORTED")
    readiness = production_readiness()
    return _execute_native_source_install_transaction(readiness)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the content-addressed Plamen native supervisor extension")
    parser.add_argument("--output-root", type=Path)
    variants = parser.add_mutually_exclusive_group()
    variants.add_argument("--test-only", action="store_true")
    variants.add_argument("--test-production-shape", action="store_true")
    variants.add_argument("--production-readiness", action="store_true")
    variants.add_argument("--source-freeze-candidate", action="store_true")
    variants.add_argument("--install-codex", action="store_true")
    parser.add_argument(
        "--target-platform",
        choices=("darwin-arm64", "linux-x86_64", "linux-arm64"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_args(sys.argv[1:] if argv is None else argv)
    if (
        arguments.target_platform is not None
        and not arguments.source_freeze_candidate
    ):
        print(
            "native supervisor build failed: --target-platform is valid only "
            "with --source-freeze-candidate",
            file=sys.stderr,
        )
        return 2
    if arguments.production_readiness:
        sys.stdout.buffer.write(_canonical_json_bytes(production_readiness()))
        return 0
    if arguments.source_freeze_candidate:
        try:
            target = arguments.target_platform or _production_host_platform_key()
            candidate = (
                render_linux_source_freeze_candidate(target)
                if target.startswith("linux-")
                else render_production_source_freeze_candidate()
            )
        except (BuildError, OSError, ValueError) as exc:
            print(f"native source freeze observation failed: {exc}", file=sys.stderr)
            return 2
        sys.stdout.buffer.write(candidate)
        return 0
    if arguments.install_codex:
        try:
            result = install_codex_from_source()
        except (BuildError, OSError, ValueError) as exc:
            print(f"native source install failed: {exc}", file=sys.stderr)
            return 2
        sys.stdout.buffer.write(_canonical_json_bytes(result))
        return 0
    if arguments.output_root is None:
        print("native supervisor build failed: --output-root is required", file=sys.stderr)
        return 2
    try:
        result = (
            TEST_ONLY_build_production_shape(arguments.output_root)
            if arguments.test_production_shape
            else build(arguments.output_root, test_only=arguments.test_only)
        )
    except (BuildError, OSError, ValueError) as exc:
        print(f"native supervisor build failed: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical_json_bytes(result)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
