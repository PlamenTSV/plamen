from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native" / "posix" / "plamen_native_installer_v2.c"
HEADER = ROOT / "native" / "posix" / "plamen_native_installer_v2.h"

MEMBERS = (
    # The specialized companion remains auxiliary to the exact generation.
    ("bin/plamen-native-launcher", 0o500),
    ("lib/plamen/plamen-audit-broker-v2", 0o500),
    ("lib/plamen/_plamen_native_supervisor.cpython-312-darwin.so", 0o400),
    ("share/plamen/plamen_broker_v2.h", 0o400),
    ("share/plamen/native-supervisor-schema-v2.json", 0o400),
    ("bin/python3.12", 0o500),
    ("lib/plamen/runtime/scripts/posix_audit_entrypoint.py", 0o400),
    ("share/plamen/runtime-package-manifest-v2.bin", 0o400),
    ("libexec/plamen-native-installer-v2", 0o500),
    ("libexec/plamen-native-source-bootstrap-coordinator-v1", 0o500),
)
SPECIALIZED_COMPANION = "share/plamen/image-member-receipt-v2.bin"


@pytest.fixture(scope="module")
def installer(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C11 compiler is required")
    output = tmp_path_factory.mktemp("native-installer-v2") / "installer"
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DPLAMEN_NATIVE_INSTALLER_V2_MAIN",
            "-DPLAMEN_NATIVE_INSTALLER_V2_TESTING",
            str(SOURCE),
            "-o",
            str(output),
        ],
        check=True,
        cwd=ROOT,
        timeout=30,
    )
    return output


@pytest.fixture(autouse=True)
def restore_fixture_permissions(tmp_path: Path):
    yield
    for current, directories, files in os.walk(tmp_path, topdown=False,
                                               followlinks=False):
        for name in files:
            path = Path(current) / name
            if not path.is_symlink():
                path.chmod(0o600)
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink():
                path.chmod(0o700)
    tmp_path.chmod(0o700)


def _topology(tmp_path: Path) -> tuple[Path, Path]:
    install_root = tmp_path / "install"
    staging = tmp_path / "staging"
    for directory in (
        install_root,
        install_root / "generations",
        install_root / "bin",
        install_root / "share",
        install_root / "share" / "plamen",
        staging,
    ):
        directory.mkdir()
        directory.chmod(0o700)
    return install_root, staging


def _stage(staging: Path, label: str, *,
           specialized: bool = False) -> tuple[Path, str]:
    generation = staging / f"stage-{label}"
    generation.mkdir(mode=0o700)
    for index, (relative, mode) in enumerate(MEMBERS, 1):
        path = generation / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"{label}:{index}:{relative}\n".encode())
        path.chmod(mode)
    if specialized:
        companion = generation / SPECIALIZED_COMPANION
        companion.write_bytes(b"PLIMGV2\0" + bytes(2808))
        companion.chmod(0o400)
    for name, payload in (
        ("com.plamen.audit.broker.v2.plist", b"<plist>broker</plist>\n"),
        ("com.plamen.audit.process-custody.v2.plist",
         b"<plist>custody</plist>\n"),
    ):
        path = generation / "Library" / "LaunchAgents" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o400)
    directories = sorted(
        (path for path in generation.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        directory.chmod(0o500)
    # Darwin requires the directory being renamed to retain owner write access.
    # The native publisher removes it immediately after the atomic rename.
    generation.chmod(0o700)
    generation_id, _roster = _intrinsic_digests(generation)
    return generation, generation_id


def _intrinsic_digests(generation: Path) -> tuple[str, bytes]:
    rows = bytearray()
    for role, (relative, mode) in enumerate(MEMBERS, 1):
        path = generation / relative
        encoded = relative.encode("ascii")
        payload = path.read_bytes()
        rows.extend(struct.pack(">HHIQ", role, len(encoded), mode, len(payload)))
        rows.extend(hashlib.sha256(payload).digest())
        rows.extend(encoded)
    count = struct.pack(">H", len(MEMBERS))
    roster = hashlib.sha256(
        b"PLAMEN-INTRINSIC-ROSTER-V2\0" + count + rows
    ).digest()
    generation_id = hashlib.sha256(
        b"PLAMEN-INTRINSIC-GENERATION-V2\0"
        + struct.pack(">HHHH", 2, 1, 1, len(MEMBERS))
        + rows
    ).hexdigest()
    return generation_id, roster


def _receipt(generation: Path, generation_id: str, final_path: Path,
             output: Path, *, specialized: bool = False) -> bytes:
    record = bytearray(16384)
    record[:8] = b"PLMINS2\0"
    struct.pack_into(">HHI", record, 8, 2, 256, 16384)
    record[16:48] = bytes.fromhex(generation_id)
    derived_generation, intrinsic_roster = _intrinsic_digests(generation)
    assert derived_generation == generation_id
    record[48:80] = intrinsic_roster
    struct.pack_into(">H", record, 112, len(MEMBERS))
    record[128:160] = hashlib.sha256(b"projection-schema").digest()
    record[160:192] = hashlib.sha256(b"protocol-schema").digest()
    encoded_path = os.fsencode(final_path)
    assert 0 < len(encoded_path) <= 1024
    struct.pack_into(">H", record, 122, len(encoded_path))
    record[320:320 + len(encoded_path)] = encoded_path
    plist_rows = (
        ("com.plamen.audit.broker.v2.plist", 124, 1344, 2368),
        ("com.plamen.audit.process-custody.v2.plist", 126, 11456, 12480),
    )
    for name, length_offset, path_offset, identity_offset in plist_rows:
        staged = generation / "Library" / "LaunchAgents" / name
        installed = final_path / "Library" / "LaunchAgents" / name
        encoded = os.fsencode(installed)
        information = staged.stat(follow_symlinks=False)
        struct.pack_into(">H", record, length_offset, len(encoded))
        record[path_offset:path_offset + len(encoded)] = encoded
        record[identity_offset:identity_offset + 32] = hashlib.sha256(
            staged.read_bytes()
        ).digest()
        struct.pack_into(">QQQIII", record, identity_offset + 32,
                         information.st_size, information.st_dev,
                         information.st_ino, 0o400, information.st_uid,
                         information.st_gid)
    for index, (relative, mode) in enumerate(MEMBERS):
        path = generation / relative
        information = path.stat(follow_symlinks=False)
        row = 2496 + index * 896
        encoded_relative = relative.encode("ascii")
        struct.pack_into(">HHHHHH", record, row,
                         index + 1, len(encoded_relative), 0, 0, 0, 0)
        struct.pack_into(">IQQQII", record, row + 12, mode,
                         information.st_size, information.st_dev,
                         information.st_ino, information.st_uid,
                         information.st_gid)
        record[row + 48:row + 80] = hashlib.sha256(path.read_bytes()).digest()
        record[row + 112:row + 112 + len(encoded_relative)] = encoded_relative
    if specialized:
        companion = generation / SPECIALIZED_COMPANION
        manifest = generation / MEMBERS[7][0]
        information = companion.stat(follow_symlinks=False)
        auxiliary = 12608
        encoded = SPECIALIZED_COMPANION.encode("ascii")
        struct.pack_into(">I", record, 192, 1)
        record[auxiliary:auxiliary + 8] = b"PLMIRA1\0"
        struct.pack_into(">HHIH", record, auxiliary + 8,
                         1, 512, 1, len(encoded))
        record[auxiliary + 24:auxiliary + 56] = hashlib.sha256(
            manifest.read_bytes()
        ).digest()
        record[auxiliary + 56:auxiliary + 88] = hashlib.sha256(
            companion.read_bytes()
        ).digest()
        struct.pack_into(">QQQIII", record, auxiliary + 88,
                         information.st_size, information.st_dev,
                         information.st_ino, 0o400, information.st_uid,
                         information.st_gid)
        record[auxiliary + 128:auxiliary + 128 + len(encoded)] = encoded
    checkpoint_input = bytearray(record[:16352])
    checkpoint_input[80:112] = bytes(32)
    record[80:112] = hashlib.sha256(
        b"PLAMEN-INSTALL-PRECOMMIT-V2\0" + checkpoint_input
    ).digest()
    record[16352:] = hashlib.sha256(record[:16352]).digest()
    output.write_bytes(record)
    output.chmod(0o400)
    return bytes(record)


def _reseal_receipt(record: bytearray) -> None:
    checkpoint_input = bytearray(record[:16352])
    checkpoint_input[80:112] = bytes(32)
    record[80:112] = hashlib.sha256(
        b"PLAMEN-INSTALL-PRECOMMIT-V2\0" + checkpoint_input
    ).digest()
    record[16352:] = hashlib.sha256(record[:16352]).digest()


def _publish(installer: Path, install_root: Path, staging: Path,
             generation: Path, generation_id: str, receipt: Path,
             crash_phase: int | None = None, *,
             specialized: bool = False,
             retained_companion: Path | None = None,
             ) -> subprocess.CompletedProcess[str]:
    command = [
        str(installer),
        "publish-specialized" if specialized else "publish",
        str(install_root), str(staging),
        generation.name, generation_id, str(receipt),
    ]
    if specialized:
        command.append(str(retained_companion or
                           generation / SPECIALIZED_COMPANION))
    if crash_phase is not None:
        command.append(str(crash_phase))
    return subprocess.run(command, text=True, capture_output=True,
                          check=False, timeout=20)


def _recover(installer: Path, install_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(installer), "recover", str(install_root)],
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )


def _validate_installed(
    installer: Path, install_root: Path, receipt: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(installer), "validate-installed", str(install_root), str(receipt)],
        text=True, capture_output=True, check=False, timeout=20,
    )


def _publish_deploy(
    installer: Path,
    install_root: Path,
    staging: Path,
    generation: Path,
    generation_id: str,
    receipt: Path,
    log: Path,
    crash_phase: int | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        str(installer), "publish-deploy", str(install_root), str(staging),
        generation.name, generation_id, str(receipt), str(log),
    ]
    if crash_phase is not None:
        command.append(str(crash_phase))
    return subprocess.run(command, text=True, capture_output=True,
                          check=False, timeout=20)


def _recover_deploy(
    installer: Path, install_root: Path, log: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(installer), "recover-deploy", str(install_root), str(log)],
        text=True, capture_output=True, check=False, timeout=20,
    )


def _publish_retained_deploy(
    installer: Path, install_root: Path, staging: Path, generation: Path,
    generation_id: str, receipt: Path, log: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(installer), "publish-retained-deploy", str(install_root),
         str(staging), generation.name, generation_id, str(receipt), str(log)],
        text=True, capture_output=True, check=False, timeout=20,
    )


def _rollback_retained_deploy(
    installer: Path, install_root: Path, successor: Path,
    prior: Path | None, log: Path, crash: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = [
        str(installer), "rollback-retained-deploy", str(install_root),
        str(successor), "-" if prior is None else str(prior), str(log),
    ]
    if crash:
        command.append("9")
    return subprocess.run(
        command, text=True, capture_output=True, check=False, timeout=20,
    )


def _finalize_retained_deploy(
    installer: Path, install_root: Path, successor: Path, log: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(installer), "finalize-retained-deploy", str(install_root),
         str(successor), str(log)],
        text=True, capture_output=True, check=False, timeout=20,
    )


def _assert_no_transaction_debris(install_root: Path) -> None:
    assert not (install_root / ".plamen-native-install-v2.transaction").exists()
    assert not (install_root / ".plamen-native-install-v2.transaction.next").exists()
    assert not (install_root / "bin" / ".plamen-native-launcher.next-v2").exists()
    assert not (install_root / "bin" / ".plamen-native-launcher.rollback-v2").exists()
    assert not (install_root / "share" / "plamen" /
                ".native-install-receipt-v2.next-v2").exists()
    assert not (install_root / "share" / "plamen" /
                ".native-install-receipt-v2.rollback-v2").exists()


def test_fresh_publish_is_receipt_first_and_launcher_is_generation_hardlink(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "a")
    receipt_path = tmp_path / "receipt-a.bin"
    receipt = _receipt(
        generation, generation_id,
        install_root / "generations" / generation_id, receipt_path,
    )
    completed = _publish(
        installer, install_root, staging, generation, generation_id,
        receipt_path,
    )
    assert completed.returncode == 0, completed.stderr
    installed_generation = install_root / "generations" / generation_id
    stable = install_root / "bin" / "plamen-native-launcher"
    launcher = installed_generation / "bin" / "plamen-native-launcher"
    assert not generation.exists()
    assert installed_generation.is_dir()
    assert stable.stat().st_ino == launcher.stat().st_ino
    assert stable.stat().st_dev == launcher.stat().st_dev
    assert stable.stat().st_nlink == 2
    assert stat.S_IMODE(stable.stat().st_mode) == 0o500
    active_receipt = (
        install_root / "share" / "plamen" / "native-install-receipt-v2.bin"
    )
    assert active_receipt.read_bytes() == receipt
    assert stat.S_IMODE(active_receipt.stat().st_mode) == 0o400
    _assert_no_transaction_debris(install_root)


def test_read_only_installed_validator_rejects_foreign_receipt_and_drift(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "validate")
    receipt_path = tmp_path / "receipt.bin"
    _receipt(generation, generation_id,
             install_root / "generations" / generation_id, receipt_path)
    assert _publish(installer, install_root, staging, generation,
                    generation_id, receipt_path).returncode == 0
    assert _validate_installed(
        installer, install_root, receipt_path,
    ).returncode == 0

    foreign, foreign_id = _stage(staging, "foreign-validate")
    foreign_receipt = tmp_path / "foreign.bin"
    _receipt(foreign, foreign_id,
             install_root / "generations" / foreign_id, foreign_receipt)
    assert _validate_installed(
        installer, install_root, foreign_receipt,
    ).returncode == 75
    stable = install_root / "bin/plamen-native-launcher"
    stable.chmod(0o700)
    assert _validate_installed(
        installer, install_root, receipt_path,
    ).returncode == 75


def test_crash_after_receipt_rolls_back_then_existing_generation_republishes(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation_a, generation_a_id = _stage(staging, "a")
    receipt_a_path = tmp_path / "receipt-a.bin"
    receipt_a = _receipt(
        generation_a, generation_a_id,
        install_root / "generations" / generation_a_id, receipt_a_path,
    )
    assert _publish(installer, install_root, staging, generation_a,
                    generation_a_id, receipt_a_path).returncode == 0
    stable = install_root / "bin" / "plamen-native-launcher"
    old_launcher = stable.read_bytes()

    generation_b, generation_b_id = _stage(staging, "b")
    receipt_b_path = tmp_path / "receipt-b.bin"
    receipt_b = _receipt(
        generation_b, generation_b_id,
        install_root / "generations" / generation_b_id, receipt_b_path,
    )
    crashed = _publish(
        installer, install_root, staging, generation_b, generation_b_id,
        receipt_b_path, crash_phase=4,
    )
    assert crashed.returncode == 99
    assert (install_root / ".plamen-native-install-v2.transaction").is_file()
    assert (install_root / "share" / "plamen" /
            "native-install-receipt-v2.bin").read_bytes() == receipt_b
    assert stable.read_bytes() == old_launcher
    assert (install_root / "generations" / generation_b_id).is_dir()

    recovered = _recover(installer, install_root)
    assert recovered.returncode == 0, recovered.stderr
    assert stable.read_bytes() == old_launcher
    assert (install_root / "share" / "plamen" /
            "native-install-receipt-v2.bin").read_bytes() == receipt_a
    _assert_no_transaction_debris(install_root)

    republished = _publish(
        installer, install_root, staging, generation_b, generation_b_id,
        receipt_b_path,
    )
    assert republished.returncode == 0, republished.stderr
    assert stable.read_bytes().startswith(b"b:1:")
    assert (install_root / "share" / "plamen" /
            "native-install-receipt-v2.bin").read_bytes() == receipt_b
    _assert_no_transaction_debris(install_root)


def test_committed_crash_finalizes_new_pair_instead_of_rolling_back(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "committed")
    receipt_path = tmp_path / "receipt.bin"
    receipt = _receipt(
        generation, generation_id,
        install_root / "generations" / generation_id, receipt_path,
    )
    crashed = _publish(
        installer, install_root, staging, generation, generation_id,
        receipt_path, crash_phase=8,
    )
    assert crashed.returncode == 99
    recovered = _recover(installer, install_root)
    assert recovered.returncode == 0, recovered.stderr
    assert (install_root / "bin" / "plamen-native-launcher").read_bytes(
    ).startswith(b"committed:1:")
    assert (install_root / "share" / "plamen" /
            "native-install-receipt-v2.bin").read_bytes() == receipt
    _assert_no_transaction_debris(install_root)


def test_deployment_effect_is_precommit_and_committed_recovery_is_idempotent(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "deploy")
    receipt_path = tmp_path / "receipt.bin"
    _receipt(generation, generation_id,
             install_root / "generations" / generation_id, receipt_path)
    log = tmp_path / "deployment.log"
    crashed = _publish_deploy(
        installer, install_root, staging, generation, generation_id,
        receipt_path, log, crash_phase=8,
    )
    assert crashed.returncode == 99
    assert log.read_text() == "PA"
    # Ordinary recovery has no authority to infer or repair launchd state.
    denied = _recover(installer, install_root)
    assert denied.returncode == 75
    recovered = _recover_deploy(installer, install_root, log)
    assert recovered.returncode == 0, recovered.stderr
    assert log.read_text() == "PAC"
    _assert_no_transaction_debris(install_root)


def test_retained_commit_requires_exact_resolution_and_rollback_is_idempotent(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "retained")
    receipt_path = tmp_path / "receipt.bin"
    _receipt(generation, generation_id,
             install_root / "generations" / generation_id, receipt_path)
    foreign_generation, foreign_id = _stage(staging, "foreign")
    foreign_receipt = tmp_path / "foreign.bin"
    _receipt(foreign_generation, foreign_id,
             install_root / "generations" / foreign_id, foreign_receipt)
    log = tmp_path / "deployment.log"

    published = _publish_retained_deploy(
        installer, install_root, staging, generation, generation_id,
        receipt_path, log,
    )
    assert published.returncode == 0, published.stderr
    assert log.read_text() == "PAC"
    assert (install_root / ".plamen-native-install-v2.transaction").is_file()
    assert _recover_deploy(installer, install_root, log).returncode == 75
    denied = _rollback_retained_deploy(
        installer, install_root, foreign_receipt, None, log,
    )
    assert denied.returncode == 75
    assert (install_root / "bin/plamen-native-launcher").read_bytes(
    ).startswith(b"retained:1:")

    rolled_back = _rollback_retained_deploy(
        installer, install_root, receipt_path, None, log,
    )
    assert rolled_back.returncode == 0, rolled_back.stderr
    assert log.read_text() == "PACRS"
    assert not (install_root / "bin/plamen-native-launcher").exists()
    assert not (install_root / "share/plamen/native-install-receipt-v2.bin").exists()
    _assert_no_transaction_debris(install_root)
    replay = _rollback_retained_deploy(
        installer, install_root, receipt_path, None, log,
    )
    assert replay.returncode == 0, replay.stderr
    assert log.read_text() == "PACRS"


def test_retained_commit_rollback_recovers_durable_direction_to_exact_prior(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    first, first_id = _stage(staging, "first")
    first_receipt = tmp_path / "first.bin"
    first_bytes = _receipt(first, first_id,
        install_root / "generations" / first_id, first_receipt)
    log = tmp_path / "deployment.log"
    assert _publish_deploy(installer, install_root, staging, first, first_id,
                           first_receipt, log).returncode == 0
    second, second_id = _stage(staging, "second")
    second_receipt = tmp_path / "second.bin"
    _receipt(second, second_id,
        install_root / "generations" / second_id, second_receipt)
    assert _publish_retained_deploy(
        installer, install_root, staging, second, second_id,
        second_receipt, log,
    ).returncode == 0

    crashed = _rollback_retained_deploy(
        installer, install_root, second_receipt, first_receipt, log,
        crash=True,
    )
    assert crashed.returncode == 99
    marker = install_root / ".plamen-native-install-v2.transaction"
    assert marker.is_file()
    assert int.from_bytes(marker.read_bytes()[10:12], "big") == 9
    recovered = _recover_deploy(installer, install_root, log)
    assert recovered.returncode == 0, recovered.stderr
    assert (install_root / "bin/plamen-native-launcher").read_bytes(
    ).startswith(b"first:1:")
    assert (install_root / "share/plamen/native-install-receipt-v2.bin").read_bytes(
    ) == first_bytes
    _assert_no_transaction_debris(install_root)
    replay = _rollback_retained_deploy(
        installer, install_root, second_receipt, first_receipt, log,
    )
    assert replay.returncode == 0, replay.stderr


def test_retained_commit_finalize_is_exact_and_idempotent(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "final")
    receipt_path = tmp_path / "receipt.bin"
    _receipt(generation, generation_id,
             install_root / "generations" / generation_id, receipt_path)
    foreign, foreign_id = _stage(staging, "foreign-final")
    foreign_receipt = tmp_path / "foreign.bin"
    _receipt(foreign, foreign_id,
             install_root / "generations" / foreign_id, foreign_receipt)
    log = tmp_path / "deployment.log"
    assert _publish_retained_deploy(
        installer, install_root, staging, generation, generation_id,
        receipt_path, log,
    ).returncode == 0
    assert _finalize_retained_deploy(
        installer, install_root, foreign_receipt, log,
    ).returncode == 75
    finalized = _finalize_retained_deploy(
        installer, install_root, receipt_path, log,
    )
    assert finalized.returncode == 0, finalized.stderr
    assert log.read_text() == "PACC"
    _assert_no_transaction_debris(install_root)
    replay = _finalize_retained_deploy(
        installer, install_root, receipt_path, log,
    )
    assert replay.returncode == 0, replay.stderr
    assert log.read_text() == "PACC"


@pytest.mark.parametrize("phase", [5, 6])
def test_deployment_precommit_crash_requires_authorized_rollback(
    installer: Path, tmp_path: Path, phase: int,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, f"deploy-{phase}")
    receipt_path = tmp_path / "receipt.bin"
    _receipt(generation, generation_id,
             install_root / "generations" / generation_id, receipt_path)
    log = tmp_path / "deployment.log"
    crashed = _publish_deploy(
        installer, install_root, staging, generation, generation_id,
        receipt_path, log, crash_phase=phase,
    )
    assert crashed.returncode == 99
    assert log.read_text() == ("P" if phase == 5 else "PA")
    assert _recover(installer, install_root).returncode == 75
    recovered = _recover_deploy(installer, install_root, log)
    assert recovered.returncode == 0, recovered.stderr
    # R revokes replacement effects before the generic installer restores the
    # old receipt/launcher; S restores prior effects only afterward.
    assert log.read_text().endswith("RS")
    assert not (install_root / "bin" / "plamen-native-launcher").exists()
    _assert_no_transaction_debris(install_root)


@pytest.mark.parametrize("phase", [1, 2, 3, 4, 7])
def test_first_install_crash_rolls_back_to_no_active_pair(
    installer: Path, tmp_path: Path, phase: int,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, f"first-{phase}")
    receipt_path = tmp_path / "receipt.bin"
    _receipt(
        generation, generation_id,
        install_root / "generations" / generation_id, receipt_path,
    )
    assert _publish(installer, install_root, staging, generation,
                    generation_id, receipt_path, crash_phase=phase).returncode == 99
    recovered = _recover(installer, install_root)
    assert recovered.returncode == 0, recovered.stderr
    assert not (install_root / "bin" / "plamen-native-launcher").exists()
    assert not (install_root / "share" / "plamen" /
                "native-install-receipt-v2.bin").exists()
    _assert_no_transaction_debris(install_root)


def test_tampered_receipt_fails_before_any_publication(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "tamper")
    receipt_path = tmp_path / "receipt.bin"
    raw = bytearray(_receipt(
        generation, generation_id,
        install_root / "generations" / generation_id, receipt_path,
    ))
    raw[4096] ^= 1
    receipt_path.chmod(0o600)
    receipt_path.write_bytes(raw)
    receipt_path.chmod(0o400)
    completed = _publish(
        installer, install_root, staging, generation, generation_id,
        receipt_path,
    )
    assert completed.returncode == 75
    assert completed.stderr == "Plamen native install denied.\n"
    assert generation.is_dir()
    assert not any((install_root / "generations").iterdir())
    assert not (install_root / "bin" / "plamen-native-launcher").exists()
    _assert_no_transaction_debris(install_root)


def test_resealed_forged_intrinsic_roster_is_rejected(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "forged-roster")
    receipt_path = tmp_path / "receipt.bin"
    raw = bytearray(_receipt(
        generation, generation_id,
        install_root / "generations" / generation_id, receipt_path,
    ))
    raw[48:80] = hashlib.sha256(b"attacker-selected-roster").digest()
    _reseal_receipt(raw)
    receipt_path.chmod(0o600)
    receipt_path.write_bytes(raw)
    receipt_path.chmod(0o400)
    completed = _publish(
        installer, install_root, staging, generation, generation_id,
        receipt_path,
    )
    assert completed.returncode == 75
    assert not any((install_root / "generations").iterdir())


def test_resealed_caller_selected_generation_id_is_rejected(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "forged-generation")
    receipt_path = tmp_path / "receipt.bin"
    raw = bytearray(_receipt(
        generation, generation_id,
        install_root / "generations" / generation_id, receipt_path,
    ))
    forged = hashlib.sha256(b"attacker-selected-generation").hexdigest()
    raw[16:48] = bytes.fromhex(forged)
    generation_path_size = struct.unpack_from(">H", raw, 122)[0]
    original_path = bytes(raw[320:320 + generation_path_size]).decode("ascii")
    forged_path = original_path.removesuffix(generation_id) + forged
    assert len(forged_path) == generation_path_size
    raw[320:320 + generation_path_size] = forged_path.encode("ascii")
    _reseal_receipt(raw)
    receipt_path.chmod(0o600)
    receipt_path.write_bytes(raw)
    receipt_path.chmod(0o400)
    completed = _publish(
        installer, install_root, staging, generation, forged, receipt_path,
    )
    assert completed.returncode == 75
    assert not any((install_root / "generations").iterdir())


def test_writable_or_symlinked_staged_content_is_rejected(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "unsafe")
    receipt_path = tmp_path / "receipt.bin"
    _receipt(
        generation, generation_id,
        install_root / "generations" / generation_id, receipt_path,
    )
    unsafe = generation / "share" / "plamen" / "native-supervisor-schema-v2.json"
    unsafe.chmod(0o600)
    completed = _publish(
        installer, install_root, staging, generation, generation_id,
        receipt_path,
    )
    assert completed.returncode == 75
    assert generation.is_dir()
    assert not any((install_root / "generations").iterdir())

    unsafe.parent.chmod(0o700)
    unsafe.unlink()
    unsafe.symlink_to(generation / "share" / "plamen" / "plamen_broker_v2.h")
    unsafe.parent.chmod(0o500)
    completed = _publish(
        installer, install_root, staging, generation, generation_id,
        receipt_path,
    )
    assert completed.returncode == 75
    assert generation.is_dir()


def test_corrupt_recovery_marker_fails_closed_without_changing_active_pair(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(staging, "stable")
    receipt_path = tmp_path / "receipt.bin"
    _receipt(
        generation, generation_id,
        install_root / "generations" / generation_id, receipt_path,
    )
    assert _publish(installer, install_root, staging, generation,
                    generation_id, receipt_path).returncode == 0
    stable = install_root / "bin" / "plamen-native-launcher"
    before_launcher = stable.read_bytes()
    active_receipt = (
        install_root / "share" / "plamen" / "native-install-receipt-v2.bin"
    )
    before_receipt = active_receipt.read_bytes()
    marker = install_root / ".plamen-native-install-v2.transaction"
    marker.write_bytes(b"x" * 320)
    marker.chmod(0o400)
    recovered = _recover(installer, install_root)
    assert recovered.returncode == 75
    assert stable.read_bytes() == before_launcher
    assert active_receipt.read_bytes() == before_receipt
    assert marker.read_bytes() == b"x" * 320


def test_source_contract_has_no_environment_home_shell_or_path_reopen_authority() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    for forbidden in ("getenv(", "secure_getenv(", "system(", "popen(",
                      " HOME", "$HOME", "/bin/sh", "realpath("):
        assert forbidden not in source
    assert "generation_member_fds[PLAMEN_NATIVE_INSTALLER_V2_MEMBER_COUNT]" in header
    assert "renameat(" in source
    assert "linkat(" in source
    assert "fsync(" in source
    assert "O_NOFOLLOW" in source
    assert "F_SETLK" in source


def test_specialized_publish_is_launcher_last_and_rolls_back_atomically(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation_a, generation_a_id = _stage(
        staging, "specialized-a", specialized=True,
    )
    companion_a = generation_a / SPECIALIZED_COMPANION
    companion_a_bytes = companion_a.read_bytes()
    receipt_a_path = tmp_path / "receipt-a.bin"
    receipt_a = _receipt(
        generation_a, generation_a_id,
        install_root / "generations" / generation_a_id,
        receipt_a_path, specialized=True,
    )
    published = _publish(
        installer, install_root, staging, generation_a, generation_a_id,
        receipt_a_path, specialized=True,
    )
    assert published.returncode == 0, published.stderr
    installed_a = install_root / "generations" / generation_a_id
    assert (installed_a / SPECIALIZED_COMPANION).read_bytes() \
        == companion_a_bytes
    assert stat.S_IMODE(
        (installed_a / SPECIALIZED_COMPANION).stat().st_mode
    ) == 0o400
    assert (install_root / "share" / "plamen" /
            "native-install-receipt-v2.bin").read_bytes() == receipt_a
    stable = install_root / "bin" / "plamen-native-launcher"
    old_launcher = stable.read_bytes()

    generation_b, generation_b_id = _stage(
        staging, "specialized-b", specialized=True,
    )
    receipt_b_path = tmp_path / "receipt-b.bin"
    _receipt(
        generation_b, generation_b_id,
        install_root / "generations" / generation_b_id,
        receipt_b_path, specialized=True,
    )
    crashed = _publish(
        installer, install_root, staging, generation_b, generation_b_id,
        receipt_b_path, crash_phase=4, specialized=True,
    )
    assert crashed.returncode == 99
    assert stable.read_bytes() == old_launcher
    recovered = _recover(installer, install_root)
    assert recovered.returncode == 0, recovered.stderr
    assert stable.read_bytes() == old_launcher
    assert (install_root / "share" / "plamen" /
            "native-install-receipt-v2.bin").read_bytes() == receipt_a
    _assert_no_transaction_debris(install_root)


def test_specialized_publish_rejects_same_byte_foreign_retained_companion(
    installer: Path, tmp_path: Path,
) -> None:
    install_root, staging = _topology(tmp_path)
    generation, generation_id = _stage(
        staging, "specialized-foreign", specialized=True,
    )
    companion = generation / SPECIALIZED_COMPANION
    receipt_path = tmp_path / "receipt.bin"
    _receipt(
        generation, generation_id,
        install_root / "generations" / generation_id,
        receipt_path, specialized=True,
    )
    replacement = tmp_path / "foreign-companion.bin"
    replacement.write_bytes(companion.read_bytes())
    replacement.chmod(0o400)
    rejected = _publish(
        installer, install_root, staging, generation, generation_id,
        receipt_path, specialized=True, retained_companion=replacement,
    )
    assert rejected.returncode == 75
    assert generation.is_dir()
    assert not any((install_root / "generations").iterdir())
    assert not (install_root / "bin" / "plamen-native-launcher").exists()
    _assert_no_transaction_debris(install_root)
