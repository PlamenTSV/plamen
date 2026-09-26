from __future__ import annotations

import importlib.util
from pathlib import Path
from types import MappingProxyType, ModuleType

import pytest


ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "scripts" / "build_posix_native_supervisor.py"


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_plamen_operation4_execution_root_test", BUILDER,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Roster:
    _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True


class _RoleAuthority:
    def __init__(self, marker: str):
        setattr(self, marker, True)
        self.closed = False

    def close(self):
        self.closed = True
        return True


class _FixedPreparation:
    def __init__(self, events: list[str]):
        self.events = events
        self.closed = False

    def materialized_inputs(self):
        self.events.append("fixed-materialized")
        return tuple(object() for _ in range(7))

    def issue(self, **values):
        assert values["coordinator"]["kind"] == (
            "retained-source-bootstrap-coordinator"
        )
        assert len(values["materialized_inputs"]) == 7
        self.events.append("fixed-issued")
        return tuple(object() for _ in range(7))

    def close(self):
        self.events.append("fixed-closed")
        self.closed = True
        return True


class _PrivateStore:
    def __init__(self, descriptor: int):
        self.descriptor = descriptor


class _NativeStage:
    _PLAMEN_PRODUCTION_NATIVE_STAGE_AUTHORITY_V1 = True

    def __init__(self):
        self.closed = False

    def stage(self, *args):
        return ("stage", args)

    def validate_stage(self, *args):
        return True

    def commit(self, *args):
        return ("commit", args)

    def validate_installed(self, *args):
        return ("validate", args)

    def rollback(self, *args):
        return True

    def cleanup(self, *args):
        return True

    def close(self):
        self.closed = True
        return True


def _callbacks(builder, events, captured, *, malformed_fold=False):
    def compile_release(workspace, workspace_fd, _freeze, **values):
        assert workspace.is_dir()
        assert workspace_fd >= 3
        kinds = values["artifact_kinds"]
        if values["operation4_policy_rows"] is None:
            events.append("compiled-pre-policy")
        else:
            assert len(values["operation4_policy_rows"]) == 11
            events.append("compiled-policy")
        return {
            kind: {"kind": kind, "fd": -1, "path": workspace / kind}
            for kind in kinds
        }

    def seal(**values):
        assert "cpython-extension" in values["compiled_artifacts"]
        assert isinstance(values["private_store"], _PrivateStore)
        events.append("projections-sealed")
        return MappingProxyType({
            "plamen_guest": MappingProxyType({}),
            "plamen_package": MappingProxyType({}),
        })

    def prepare_fixed(**values):
        assert isinstance(values["frozen_module"], ModuleType)
        events.append("fixed-prepared")
        value = _FixedPreparation(events)
        captured["fixed"] = value
        return value

    def derive(**values):
        assert len(values["fixed_materialized_inputs"]) == 7
        events.append("policy-derived")
        return tuple(MappingProxyType({"role": role}) for role in range(11))

    def acquire_evm(**values):
        events.append("evm-acquired")
        return _RoleAuthority("_PLAMEN_RETAINED_EVM_STATIC_UPSTREAMS_V1")

    def issue_evm(**values):
        assert values["upstream_authority"] is not None
        events.append("evm-issued")
        value = _RoleAuthority(
            "_PLAMEN_RETAINED_PRODUCTION_EVM_STATIC_ROLES_V1"
        )
        captured["evm"] = value
        return value

    def acquire_backend(**values):
        events.append("backend-acquired")
        return _RoleAuthority("_PLAMEN_PRODUCTION_BACKEND_INPUTS_V1")

    def issue_backend(**values):
        assert values["input_authority"] is not None
        events.append("backend-issued")
        value = _RoleAuthority(
            "_PLAMEN_RETAINED_PRODUCTION_BACKEND_ROLES_V1"
        )
        captured["backend"] = value
        return value

    def compose(**values):
        assert len(values["fixed_role_records"]) == 7
        events.append("folded")
        count = 10 if malformed_fold else 11
        return MappingProxyType({
            "policy_rows": tuple(range(count)),
            "role_fds": tuple((role, role, role) for role in range(count)),
        })

    def bind(**values):
        owner = values["operation4"]
        captured["owner"] = owner
        assert len(owner.operation4_inputs()["role_fds"]) == 11
        assert "retained-source-bootstrap-coordinator" in (
            owner.compiled_artifacts()
        )
        events.append("stage-bound")
        value = _NativeStage()
        captured["stage"] = value
        return value

    return MappingProxyType({
        "compile_release_artifacts": compile_release,
        "seal_fixed_role_source_projections": seal,
        "prepare_production_fixed_role_inputs": prepare_fixed,
        "derive_production_operation4_policy_rows": derive,
        "acquire_production_evm_static_upstreams": acquire_evm,
        "issue_production_native_evm_static_roles": issue_evm,
        "acquire_production_backend_inputs": acquire_backend,
        "issue_production_native_backend_roles": issue_backend,
        "compose_production_operation4_inputs": compose,
        "bind_production_native_stage_authority": bind,
    })


def test_complete_private_operation4_root_binds_before_native_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    workspace = tmp_path / "workspace"; workspace.mkdir(mode=0o700)
    snapshot = workspace / "package-snapshot"; snapshot.mkdir(mode=0o700)
    events: list[str] = []
    captured: dict[str, object] = {}
    frozen = ModuleType("_frozen_fixed_role_fixture")
    frozen.RetainedPrivateStoreFactory = _PrivateStore
    monkeypatch.setattr(
        builder, "_load_frozen_source_module",
        lambda *_args, **_values: frozen,
    )
    callbacks = _callbacks(builder, events, captured)
    acquisition = builder._acquire_production_native_authority(
        home=tmp_path, source_freeze={"schema": "fixture"},
        source_authority={"schema": "source"}, source_roster=_Roster(),
        package_snapshot={"root": str(snapshot)},
        builder_callbacks=callbacks,
    )
    assert acquisition._PLAMEN_PRODUCTION_NATIVE_ACQUISITION_V1 is True
    assert events == [
        "compiled-pre-policy", "projections-sealed", "fixed-prepared",
        "fixed-materialized", "policy-derived", "compiled-policy",
        "fixed-issued", "evm-acquired", "evm-issued",
        "backend-acquired", "backend-issued", "folded", "stage-bound",
    ]
    assert acquisition.stage(1, 2) == ("stage", (1, 2))
    assert acquisition.validate_stage(1) is True
    assert acquisition.commit(3) == ("commit", (3,))
    assert acquisition.validate_installed(4) == ("validate", (4,))
    assert acquisition.rollback(5) is True
    assert acquisition.cleanup(6) is True
    operation_root = captured["owner"]._root
    assert operation_root is not None and operation_root.is_dir()
    assert acquisition.close() is True
    assert acquisition.close() is True
    assert captured["stage"].closed is True
    assert captured["fixed"].closed is True
    assert captured["backend"].closed is True
    assert captured["evm"].closed is True
    assert not operation_root.exists()


def test_missing_producer_or_stage_owner_fails_before_private_root_effect(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    workspace = tmp_path / "workspace"; workspace.mkdir(mode=0o700)
    snapshot = workspace / "package-snapshot"; snapshot.mkdir(mode=0o700)
    callbacks = builder._production_native_builder_callbacks()
    with pytest.raises(
        builder.BuildError,
        match=(
            "PRODUCTION_NATIVE_RETAINED_ACQUISITION_UNAVAILABLE:"
            "acquire_production_backend_inputs,"
            "bind_production_native_stage_authority"
        ),
    ):
        builder._acquire_production_native_authority(
            home=tmp_path, source_freeze={"schema": "fixture"},
            source_authority={"schema": "source"}, source_roster=_Roster(),
            package_snapshot={"root": str(snapshot)},
            builder_callbacks=callbacks,
        )
    assert list(workspace.iterdir()) == [snapshot]


def test_malformed_terminal_fold_closes_every_acquired_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    workspace = tmp_path / "workspace"; workspace.mkdir(mode=0o700)
    snapshot = workspace / "package-snapshot"; snapshot.mkdir(mode=0o700)
    events: list[str] = []
    captured: dict[str, object] = {}
    frozen = ModuleType("_frozen_fixed_role_fixture")
    frozen.RetainedPrivateStoreFactory = _PrivateStore
    monkeypatch.setattr(
        builder, "_load_frozen_source_module",
        lambda *_args, **_values: frozen,
    )
    callbacks = _callbacks(
        builder, events, captured, malformed_fold=True,
    )
    with pytest.raises(builder.BuildError, match="retained fold differs"):
        builder._acquire_production_native_authority(
            home=tmp_path, source_freeze={"schema": "fixture"},
            source_authority={"schema": "source"}, source_roster=_Roster(),
            package_snapshot={"root": str(snapshot)},
            builder_callbacks=callbacks,
        )
    assert "stage-bound" not in events
    assert captured["fixed"].closed is True
    assert captured["backend"].closed is True
    assert captured["evm"].closed is True
    assert list(workspace.iterdir()) == [snapshot]
