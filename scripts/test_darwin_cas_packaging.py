"""Distribution-roster contract for the Darwin native CAS source."""

from __future__ import annotations

from pathlib import Path

import build_posix_native_supervisor as NATIVE_BUILD
import toolchain_control_authority as CONTROL


ROOT = Path(__file__).resolve().parents[1]


def test_darwin_cas_helper_source_is_in_derived_runtime_package() -> None:
    helper = "scripts/darwin_cas_helper.c"

    assert (ROOT / helper).is_file()
    assert helper in CONTROL.derive_runtime_dependency_closure(ROOT)


def test_native_builder_and_all_current_production_sources_have_one_roster() -> None:
    closure = CONTROL.derive_runtime_dependency_closure(ROOT)
    assert "scripts/build_posix_native_supervisor.py" in closure

    declared = {
        relative
        for _role, relative in NATIVE_BUILD.PRODUCTION_DARWIN_SOURCE_ROSTER
    }
    observed = {
        path.relative_to(ROOT).as_posix()
        for base in (
            ROOT / "native" / "cpython",
            ROOT / "native" / "include",
            ROOT / "native" / "posix",
            ROOT / "native" / "darwin",
        )
        for path in base.iterdir()
        if path.is_file() and path.suffix in {".c", ".h", ".plist"}
        and path.name != "plamen_native_broker.c"
    }
    assert observed <= declared
    roles = [
        role for role, _relative in NATIVE_BUILD.PRODUCTION_DARWIN_SOURCE_ROSTER
    ]
    paths = [
        relative for _role, relative in NATIVE_BUILD.PRODUCTION_DARWIN_SOURCE_ROSTER
    ]
    assert len(roles) == len(set(roles))
    assert len(paths) == len(set(paths))
    assert "native/posix/plamen_native_broker.c" not in declared


def test_legacy_broker_remains_explicitly_test_only() -> None:
    helper = (ROOT / "scripts" / "TEST_ONLY_build_posix_native_broker.py").read_text()
    broker = ROOT / "native" / "posix" / "plamen_native_broker.c"

    assert broker.is_file()
    assert 'OUTPUT_NAME = "plamen_native_broker_TEST_ONLY"' in helper
    assert '"plamen.native_broker.TEST_ONLY_result.v2"' in helper
    assert "-DPLAMEN_NATIVE_BROKER_TEST_ONLY=1" in helper
    assert "PLAMEN_NATIVE_BROKER_PRODUCTION_HARDSTOP" in broker.read_text()
