"""Adversarial regressions for the durable three-launcher transaction.

This suite intentionally exercises private transaction primitives.  It uses
only isolated temporary directories and never invokes an installed Plamen
launcher or writes below the real user profile.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _secure_transaction_directory(front, directory):
    directory.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        front._win_launcher_create_directory_secure(directory)
    else:
        directory.mkdir(mode=0o700)


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_launcher_adversarial_" + uuid.uuid4().hex, ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def _selection():
    return {
        "generation_id": "npm-" + "1" * 64,
        "receipt_sha256": "2" * 64,
        "census_sha256": "3" * 64,
        "request_sha256": "4" * 64,
        "generation_policy_sha256": "5" * 64,
    }


def _make_rows(front, directory: Path, *, initialize=False):
    rows = []
    for label in ("claude", "codex", "public"):
        path = directory / f"{label}.cmd"
        old = f"{label}-old\n".encode()
        new = f"{label}-new\n".encode()
        if initialize:
            path.write_bytes(old)
        if os.path.lexists(path):
            observed = path.read_bytes()
            assert observed in {old, new}
            state = front._launcher_existing_state(
                path, observed, "adversarial live launcher"
            )
        else:
            state = front._launcher_absent_state(path)
        rows.append({
            "label": label,
            "path": path,
            "raw": new,
            "state": state,
            "admitted_predecessor_raws": (old,),
        })
    return rows


def _leave_valid_journal(front, directory: Path, rows):
    real_publish = front._launcher_transaction_publish_bytes

    class HardKill(BaseException):
        pass

    def after_journal(guard, path, raw, *, mode):
        result = real_publish(guard, path, raw, mode=mode)
        if Path(path).name == ".plamen-launcher-transaction.json":
            raise HardKill("simulated exit after durable journal")
        return result

    front._launcher_transaction_publish_bytes = after_journal
    try:
        with pytest.raises(HardKill):
            front._launcher_transaction_publish(directory, rows, _selection())
    finally:
        front._launcher_transaction_publish_bytes = real_publish
    journal = directory / ".plamen-launcher-transaction.json"
    assert journal.is_file()
    return journal, journal.read_bytes()


def test_self_digested_forgery_cannot_authorize_arbitrary_predecessor(tmp_path):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_transaction_directory(front, directory)
    rows = _make_rows(front, directory, initialize=True)
    journal_path, _ = _leave_valid_journal(front, directory, rows)
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    public = next(row for row in journal["rows"] if row["label"] == "public")
    forged = b"attacker-controlled predecessor\n"
    backup = Path(public["backup"])
    backup.write_bytes(forged)
    info = backup.stat()
    public.update({
        "predecessor_kind": "exact-existing",
        "predecessor_sha256": hashlib.sha256(forged).hexdigest(),
        "predecessor_size": len(forged),
        "predecessor_identity": [
            int(info.st_dev), int(info.st_ino), int(info.st_size), int(info.st_nlink)
        ],
        "predecessor_link_target": None,
        "predecessor_resolved_path": None,
        "predecessor_resolved_identity": None,
        "predecessor_resolved_sha256": None,
        "changed": True,
    })
    journal_path.write_bytes(front._launcher_transaction_journal_raw(journal))

    with pytest.raises(RuntimeError, match="predecessor|foreign"):
        front._launcher_transaction_publish(directory, rows, _selection())

    assert (directory / "public.cmd").read_bytes() == b"public-old\n"
    assert backup.read_bytes() == forged
    assert journal_path.exists()


@pytest.mark.parametrize("component", [".local", "bin"])
def test_static_command_directory_reparse_escape_has_zero_outside_mutation(
    tmp_path, component
):
    front = _load_front()
    user_root = tmp_path / "user"
    outside = tmp_path / "outside"
    user_root.mkdir()
    outside.mkdir()
    if component == "bin":
        (user_root / ".local").mkdir()
        link = user_root / ".local" / "bin"
    else:
        link = user_root / ".local"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks/reparse points unavailable: {exc}")

    with pytest.raises(RuntimeError, match="indirect"):
        front._launcher_safe_command_directory(user_root)

    assert list(outside.iterdir()) == []
    assert not (outside / "bin").exists()


_FRESH_PROCESS_PROGRAM = r'''
import importlib.util
import os
from pathlib import Path
import sys
import pytest  # keep Plamen's import-only bootstrap on its read-only test path

source = Path(sys.argv[1])
directory = Path(sys.argv[2])
action = sys.argv[3]
spec = importlib.util.spec_from_file_location("plamen_crash_child", source)
front = importlib.util.module_from_spec(spec)
saved = sys.argv
sys.argv = ["plamen.py"]
try:
    spec.loader.exec_module(front)
finally:
    sys.argv = saved

selection = {
    "generation_id": "npm-" + "1" * 64,
    "receipt_sha256": "2" * 64,
    "census_sha256": "3" * 64,
    "request_sha256": "4" * 64,
    "generation_policy_sha256": "5" * 64,
}

def rows_from_live():
    rows = []
    for label in ("claude", "codex", "public"):
        path = directory / (label + ".cmd")
        old = (label + "-old\n").encode()
        new = (label + "-new\n").encode()
        if os.path.lexists(path):
            observed = path.read_bytes()
            if observed not in (old, new):
                raise RuntimeError("foreign child fixture state: " + str(path))
            state = front._launcher_existing_state(path, observed, "child live launcher")
        else:
            state = front._launcher_absent_state(path)
        rows.append({
            "label": label, "path": path, "raw": new, "state": state,
            "admitted_predecessor_raws": (old,),
        })
    return rows

if action == "recover":
    for _attempt in range(3):
        front._launcher_transaction_publish(directory, rows_from_live(), selection)
        if (
            not (directory / ".plamen-launcher-transaction.json").exists()
            and all(
                (directory / (label + ".cmd")).read_bytes()
                == (label + "-new\n").encode()
                for label in ("claude", "codex", "public")
            )
        ):
            raise SystemExit(0)
    raise SystemExit(7)

real_publish = front._launcher_transaction_publish_bytes
real_rename = front._launcher_transaction_rename
real_unlink = front._launcher_transaction_unlink_exact

def publish(guard, path, raw, *, mode):
    result = real_publish(guard, path, raw, mode=mode)
    if action == "journal" and Path(path).name == ".plamen-launcher-transaction.json":
        os._exit(86)
    return result

def rename(guard, source_path, destination_path, **kwargs):
    result = real_rename(guard, source_path, destination_path, **kwargs)
    source_name = Path(source_path).name
    destination_name = Path(destination_path).name
    for label in ("claude", "codex", "public"):
        if action == "take-" + label and destination_name.endswith("-" + label + ".backup"):
            os._exit(86)
        if action == "publish-" + label and source_name.endswith("-" + label + ".stage"):
            os._exit(86)
    return result

def unlink(path, raw, label, guard=None):
    result = real_unlink(path, raw, label, guard)
    if action == "cleanup-backup" and label == "completed launcher backup":
        os._exit(86)
    if action == "cleanup-stage" and label == "completed launcher stage":
        os._exit(86)
    if action == "cleanup-journal" and label == "completed launcher journal":
        os._exit(86)
    return result

front._launcher_transaction_publish_bytes = publish
front._launcher_transaction_rename = rename
front._launcher_transaction_unlink_exact = unlink
front._launcher_transaction_publish(directory, rows_from_live(), selection)
raise SystemExit(8)
'''


@pytest.mark.parametrize(
    "seam",
    [
        "journal",
        "take-claude", "publish-claude",
        "take-codex", "publish-codex",
        "take-public", "publish-public",
        "cleanup-backup", "cleanup-stage", "cleanup-journal",
    ],
)
def test_fresh_process_recovers_hard_exit_at_every_durable_seam(tmp_path, seam):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_transaction_directory(front, directory)
    _make_rows(front, directory, initialize=True)
    command = [
        sys.executable, "-B", "-c", _FRESH_PROCESS_PROGRAM,
        str(ROOT / "plamen.py"), str(directory), seam,
    ]
    crashed = subprocess.run(command, check=False, timeout=30)
    assert crashed.returncode == 86

    recovered = subprocess.run(
        [*command[:-1], "recover"], check=False, timeout=30,
    )
    assert recovered.returncode == 0
    for label in ("claude", "codex", "public"):
        assert (directory / f"{label}.cmd").read_bytes() == f"{label}-new\n".encode()
    assert not (directory / ".plamen-launcher-transaction.json").exists()
    assert not list(directory.glob(".plamen-launcher-*.backup"))
    assert not list(directory.glob(".plamen-launcher-*.stage"))
    assert not list(directory.glob(".plamen-launcher-*.discard"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink authority regression")
def test_same_inode_same_size_symlink_target_mutation_is_rejected(tmp_path):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_transaction_directory(front, directory)
    target = directory / "legacy-target"
    target.write_bytes(b"trusted-a\n")
    launcher = directory / "public"
    launcher.symlink_to(target.name)
    admitted = {target.absolute()}
    state = front._launcher_symlink_state(launcher, admitted, "legacy launcher")
    row = {
        "label": "public", "path": launcher, "raw": b"successor\n",
        "state": state, "admitted_targets": tuple(admitted),
        "admitted_target_hashes": {
            target.absolute(): hashlib.sha256(b"trusted-a\n").hexdigest(),
        },
    }
    before = target.stat()
    target.write_bytes(b"hostile-b\n")
    after = target.stat()
    assert (before.st_dev, before.st_ino, before.st_size) == (
        after.st_dev, after.st_ino, after.st_size
    )

    with pytest.raises(RuntimeError, match="authority|hash|changed"):
        front._launcher_transaction_predecessor_authority(row)
    assert launcher.is_symlink()


def test_ordinary_postrename_source_swap_is_retracted_into_evidence(
    tmp_path, monkeypatch
):
    front = _load_front()
    source = tmp_path / "stage"
    destination = tmp_path / "public"
    expected = b"trusted-successor\n"
    foreign = b"hostile-successor!"
    assert len(expected) == len(foreign)
    source.write_bytes(expected)
    authority = front._launcher_regular_snapshot(source, expected, "staged fixture")
    real_snapshot = front._launcher_regular_snapshot
    swapped = False

    def swap_after_rename(path, raw, label):
        nonlocal swapped
        if label.startswith("published ") and Path(path) == destination and not swapped:
            swapped = True
            destination.unlink()
            destination.write_bytes(foreign)
        return real_snapshot(path, raw, label)

    monkeypatch.setattr(front, "_launcher_regular_snapshot", swap_after_rename)
    with pytest.raises(RuntimeError, match="retracted|recovery"):
        front._launcher_rename_noreplace(
            source, destination,
            expected_source_raw=expected,
            expected_source_authority=authority,
            source_label="adversarial staged launcher",
        )

    assert swapped
    assert not os.path.lexists(destination)
    evidence = list(tmp_path.glob(".public.unverified-*.recovery"))
    assert len(evidence) == 1
    assert evidence[0].read_bytes() == foreign


@pytest.mark.skipif(os.name != "nt", reason="Windows inherited-ACL migration")
def test_same_bytes_with_inherited_acl_migrate_as_one_three_row_transaction(tmp_path):
    front = _load_front()
    directory = tmp_path / "bin"
    directory.mkdir()
    rows = []
    predecessor_file_ids = {}
    for label in ("claude", "codex", "public"):
        path = directory / f"{label}.cmd"
        raw = f"{label}-already-current\n".encode()
        path.write_bytes(raw)
        state = front._launcher_existing_state(
            path, raw, "inherited-ACL launcher fixture",
        )
        assert state["security_current"] is False
        predecessor_file_ids[label] = tuple(state["authority"][:2])
        rows.append({
            "label": label, "path": path, "raw": raw, "state": state,
            "admitted_predecessor_raws": (raw,),
        })

    assert front._launcher_transaction_publish(
        directory, rows, _selection(),
    ) == "COMMITTED"
    replay_rows = []
    for row in rows:
        state = front._launcher_existing_state(
            row["path"], row["raw"], "migrated exact-ACL launcher",
        )
        assert state["security_current"] is True
        assert tuple(state["authority"][:2]) != predecessor_file_ids[row["label"]]
        replay_rows.append({**row, "state": state})
    assert front._launcher_transaction_publish(
        directory, replay_rows, _selection(),
    ) == "CURRENT"
    assert not (directory / ".plamen-launcher-transaction.json").exists()


def test_symlink_postrename_swap_is_retracted_into_evidence(tmp_path, monkeypatch):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_transaction_directory(front, directory)
    trusted = directory / "trusted-target"
    foreign = directory / "foreign-target"
    trusted.write_bytes(b"trusted\n")
    foreign.write_bytes(b"foreign\n")
    source = directory / "public"
    destination = directory / "taken"
    try:
        source.symlink_to(trusted.name)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")
    admitted = {trusted.absolute()}
    state = front._launcher_symlink_state(source, admitted, "symlink fixture")
    row = {
        "label": "public", "path": source, "raw": b"successor\n",
        "state": state, "admitted_targets": tuple(admitted),
        "admitted_target_hashes": {
            trusted.absolute(): hashlib.sha256(trusted.read_bytes()).hexdigest(),
        },
    }
    row.update(front._launcher_transaction_predecessor_authority(row))
    real_classify = front._launcher_transaction_classify
    swapped = False

    def swap_after_rename(path, successor, authority, label):
        nonlocal swapped
        if Path(path) == destination and label.endswith(" destination") and not swapped:
            swapped = True
            destination.unlink()
            destination.symlink_to(foreign.name)
        return real_classify(path, successor, authority, label)

    monkeypatch.setattr(front, "_launcher_transaction_classify", swap_after_rename)
    with front._launcher_transaction_lock(directory) as guard:
        with pytest.raises(RuntimeError, match="authority changed|retracted"):
            front._launcher_transaction_rename_symlink(
                guard, source, destination, row, "adversarial symlink take"
            )

    assert swapped
    assert not os.path.lexists(destination)
    evidence = list(directory.glob(".plamen-launcher-unverified-*.recovery"))
    assert len(evidence) == 1
    assert evidence[0].is_symlink()
    assert os.readlink(evidence[0]) == foreign.name


@pytest.mark.parametrize("variant", ["symlink", "hardlink", "oversized", "reordered"])
def test_journal_link_size_and_order_substitution_is_rejected(tmp_path, variant):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_transaction_directory(front, directory)
    rows = _make_rows(front, directory, initialize=True)
    journal, saved = _leave_valid_journal(front, directory, rows)

    if variant == "symlink":
        target = directory / "journal-target"
        target.write_bytes(saved)
        journal.unlink()
        try:
            journal.symlink_to(target.name)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"file symlinks unavailable: {exc}")
    elif variant == "hardlink":
        twin = directory / "journal-twin"
        os.link(journal, twin)
    elif variant == "oversized":
        journal.write_bytes(b"x" * 262145)
    else:
        value = json.loads(saved)
        value["rows"][0], value["rows"][1] = value["rows"][1], value["rows"][0]
        journal.write_bytes(front._launcher_transaction_journal_raw(value))

    with pytest.raises((OSError, RuntimeError, ValueError), match="indirect|oversized|order"):
        front._launcher_transaction_publish(directory, rows, _selection())
    assert os.path.lexists(journal)


def _launcher_file_snapshot(directory):
    return {
        path.name: (
            path.read_bytes(),
            tuple(
                int(value) for value in (
                    path.stat(follow_symlinks=False).st_dev,
                    path.stat(follow_symlinks=False).st_ino,
                    path.stat(follow_symlinks=False).st_size,
                    path.stat(follow_symlinks=False).st_nlink,
                )
            ),
        )
        for path in directory.iterdir()
        if path.name.endswith(".cmd")
    }


def _publish_acl_authentic_replay_journal(front, directory, journal, raw):
    """Recreate a deleted journal with the same protected artifact authority."""
    with front._launcher_transaction_lock(directory) as guard:
        published, authority = front._launcher_transaction_publish_bytes(
            guard, journal, raw, mode=0o600,
        )
    assert published and authority is not None


def test_completed_transaction_replay_is_mutation_free_idempotent_cleanup(tmp_path):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_transaction_directory(front, directory)
    initial = _make_rows(front, directory, initialize=True)
    journal, saved = _leave_valid_journal(front, directory, initial)

    assert front._launcher_transaction_publish(directory, initial, _selection()) == "RECOVERED"
    committed_rows = _make_rows(front, directory)
    assert front._launcher_transaction_publish(
        directory, committed_rows, _selection()
    ) == "COMMITTED"
    assert not journal.exists()
    _publish_acl_authentic_replay_journal(front, directory, journal, saved)
    current_rows = _make_rows(front, directory)
    launchers_before = _launcher_file_snapshot(directory)

    assert front._launcher_transaction_publish(
        directory, current_rows, _selection()
    ) == "RECOVERED"
    assert not journal.exists()
    assert _launcher_file_snapshot(directory) == launchers_before
    assert not list(directory.glob(".plamen-launcher-*.backup"))
    assert not list(directory.glob(".plamen-launcher-*.stage"))
    assert not list(directory.glob(".plamen-launcher-*.discard"))
    assert all(
        (directory / f"{label}.cmd").read_bytes() == f"{label}-new\n".encode()
        for label in ("claude", "codex", "public")
    )


@pytest.mark.parametrize("topology", ["absent", "recreated-old"])
def test_replayed_old_journal_cannot_act_on_noncurrent_topology(tmp_path, topology):
    front = _load_front()
    directory = tmp_path / "bin"
    _secure_transaction_directory(front, directory)
    initial = _make_rows(front, directory, initialize=True)
    journal, saved = _leave_valid_journal(front, directory, initial)
    assert front._launcher_transaction_publish(directory, initial, _selection()) == "RECOVERED"
    assert front._launcher_transaction_publish(
        directory, _make_rows(front, directory), _selection()
    ) == "COMMITTED"
    public = directory / "public.cmd"
    held = tmp_path / "held-public"
    if topology == "absent":
        public.rename(held)
    else:
        public.unlink()
        public.write_bytes(b"public-old\n")
    _publish_acl_authentic_replay_journal(front, directory, journal, saved)
    rows = _make_rows(front, directory)
    before = {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.is_file()
    }
    held_before = held.read_bytes() if held.exists() else None

    with pytest.raises(RuntimeError, match="predecessor|transaction"):
        front._launcher_transaction_publish(directory, rows, _selection())

    after = {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.is_file()
    }
    assert after == before
    assert (held.read_bytes() if held.exists() else None) == held_before
