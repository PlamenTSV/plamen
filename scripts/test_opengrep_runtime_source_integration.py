"""Source-freeze integration gates for the blocked OpenGrep image tranche."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import sys
from types import ModuleType

import runtime_image_materializer as materializer
import runtime_source_projection as projection


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = ROOT / "scripts" / "toolchain_control_authority.py"
BUILDER = ROOT / "scripts" / "build_posix_native_supervisor.py"

EXPECTED = (
    "scripts/opengrep_release_policy.py",
    "verification_policy/apple_container_runtime_image_generation.v1.json",
    "verification_policy/opengrep_acquisition.v1.json",
    "verification_policy/opengrep_runtime_source_manifest.v1.json",
)


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_deriver_without_module_bootstrap() -> ModuleType:
    """Load definitions only; never consume or render the checked closure."""

    name = "_opengrep_source_integration_toolchain"
    module = ModuleType(name)
    module.__file__ = str(TOOLCHAIN)
    sys.modules[name] = module
    source = TOOLCHAIN.read_text(encoding="utf-8")
    source = source.split("\n_MODULE_ROOT = Path(__file__).resolve().parents[1]", 1)[0]
    exec(compile(source, str(TOOLCHAIN), "exec"), module.__dict__)
    return module


def test_ast_runtime_closure_derives_policy_code_and_all_three_controls(
    tmp_path: Path,
) -> None:
    toolchain = _load_deriver_without_module_bootstrap()
    assert "scripts/runtime_image_materializer.py" in toolchain._RUNTIME_ENTRYPOINTS
    toolchain._RUNTIME_ENTRYPOINTS = ("scripts/runtime_image_materializer.py",)
    for relative in (
        "scripts/runtime_image_materializer.py",
        "scripts/opengrep_release_policy.py",
        "verification_policy/apple_container_runtime_image_generation.v1.json",
        "verification_policy/opengrep_acquisition.v1.json",
        "verification_policy/opengrep_runtime_source_manifest.v1.json",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    derived = set(toolchain.derive_runtime_dependency_closure(tmp_path))
    assert set(EXPECTED) <= derived
    # This is observation only.  The stale checked closure is not rewritten or
    # treated as authority by this test.
    assert not (tmp_path / toolchain._RUNTIME_CLOSURE_PATH).exists()


def test_native_source_projection_and_build_freeze_include_exact_members() -> None:
    assert {
        "verification_policy/apple_container_runtime_image_generation.v1.json",
        "verification_policy/opengrep_acquisition.v1.json",
        "verification_policy/opengrep_runtime_source_manifest.v1.json",
    } <= set(projection.RUNTIME_FIXED)
    assert set(EXPECTED) <= set(projection.NATIVE_REQUIRED)

    builder = _load(BUILDER, "_opengrep_source_integration_builder")
    roster = dict(builder.PRODUCTION_DARWIN_SOURCE_ROSTER)
    assert roster["opengrep_release_policy"] == EXPECTED[0]
    assert roster["apple_container_image_generation_policy"] == EXPECTED[1]
    assert roster["opengrep_acquisition_policy"] == EXPECTED[2]
    assert roster["opengrep_runtime_source_manifest"] == EXPECTED[3]


def test_integrated_policy_stays_explicitly_non_authoritative() -> None:
    raw = (ROOT / materializer.APPLE_CONTAINER_IMAGE_GENERATION_POLICY_PATH).read_bytes()
    value = materializer.load_apple_container_image_generation_policy(raw)
    assert value["generation"]["state"] == "CANDIDATE_BLOCKED"
    assert value["generation"]["production_authority"] is False
    assert value["composition"]["static_members"][-1]["producer_receipt"] is None
