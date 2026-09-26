"""Regression coverage for exact, bounded Python code-constant slices."""
from __future__ import annotations

import hashlib
import sys

import pytest

import typed_worker_output_authority as typed_authority
import worker_execution_receipts as W


def _bind(value: object) -> object:
    return W._trusted_code_constant_binding(value, label="slice regression")


def _sample_code() -> object:
    def sample(argument: object) -> object:
        return argument

    return sample.__code__


def test_python314_compiler_slice_constant_has_stable_binding_digest() -> None:
    parser_slices = [
        value
        for value in typed_authority._typed_json_parse_string.__code__.co_consts
        if type(value) is slice
    ]
    if sys.version_info >= (3, 14):
        assert parser_slices == [slice(None, 2, None)]

    binding = _bind(slice(None, 2, None))
    assert binding == {
        "type": "slice",
        "start": None,
        "stop": 2,
        "step": None,
    }
    assert hashlib.sha256(W._canonical_json(binding)).hexdigest() == (
        "74dd833040c643d625583602d405010e82c58364a24a00974ef82c1348081ab3"
    )


def test_nested_slice_uses_exact_immutable_literal_bindings() -> None:
    binding = _bind(
        slice(
            slice(None, True, 1),
            ("x", False),
            frozenset({b"a", 2}),
        )
    )
    assert binding == {
        "type": "slice",
        "start": {
            "type": "slice",
            "start": None,
            "stop": True,
            "step": 1,
        },
        "stop": {
            "type": "tuple",
            "items": [
                {"type": "str", "utf8_hex": "78"},
                False,
            ],
        },
        "step": {
            "type": "frozenset",
            "items": [2, {"type": "bytes", "hex": "61"}],
        },
    }
    assert binding["start"]["stop"] is True
    assert type(binding["start"]["step"]) is int


def test_slice_shaped_forgery_is_not_duck_typed() -> None:
    class ForgedSlice:
        start = None
        stop = 2
        step = None

    with pytest.raises(W.WorkerExecutionError, match="unsupported code constant"):
        _bind(ForgedSlice())


def test_callback_bearing_slice_component_is_rejected_without_callback() -> None:
    calls: list[str] = []

    class CallbackInt(int):
        def bit_length(self) -> int:
            calls.append("bit_length")
            return super().bit_length()

        def __repr__(self) -> str:
            calls.append("repr")
            return super().__repr__()

    with pytest.raises(W.WorkerExecutionError, match="unsupported code constant"):
        _bind(slice(CallbackInt(2), None, None))

    class CallbackMeta(type):
        def __eq__(cls, other: object) -> bool:
            calls.append("metaclass equality")
            return super().__eq__(other)

        def __getattribute__(cls, name: str) -> object:
            calls.append("metaclass attribute")
            return super().__getattribute__(name)

    class CallbackField(metaclass=CallbackMeta):
        pass

    calls.clear()
    with pytest.raises(W.WorkerExecutionError, match="unsupported code constant"):
        _bind(slice(CallbackField(), None, None))
    assert calls == []


def test_unsupported_nested_slice_component_and_cycle_are_rejected() -> None:
    with pytest.raises(W.WorkerExecutionError, match="unsupported code constant"):
        _bind(slice((object(),), None, None))

    value = slice(None, 1, None)
    state = W._TrustedCodeConstantBindingState()
    state.active.add(id(value))
    with pytest.raises(W.WorkerExecutionError, match="contain a cycle"):
        W._trusted_code_constant_binding(
            value,
            label="slice regression",
            _state=state,
        )


def test_nested_and_large_slice_constants_are_bounded() -> None:
    value: object = None
    for _ in range(W._TRUSTED_CODE_CONSTANT_MAX_DEPTH + 1):
        value = slice(value, None, None)
    with pytest.raises(W.WorkerExecutionError, match="maximum depth"):
        _bind(value)

    oversized = b"x" * (W._TRUSTED_CODE_CONSTANT_MAX_BYTES + 1)
    with pytest.raises(W.WorkerExecutionError, match="maximum bytes"):
        _bind(slice(oversized, None, None))


@pytest.mark.parametrize(
    "field",
    [
        "co_name",
        "co_qualname",
        "co_filename",
        "co_code",
        "co_linetable",
        "co_exceptiontable",
        "co_consts",
        "co_names",
        "co_varnames",
        "co_freevars",
        "co_cellvars",
    ],
)
def test_every_code_metadata_byte_field_shares_the_bound(field: str) -> None:
    code = _sample_code()
    huge_text = "x" * (W._TRUSTED_CODE_CONSTANT_MAX_BYTES + 1)
    huge_bytes = b"\x00\x00" * (
        W._TRUSTED_CODE_CONSTANT_MAX_BYTES // 2 + 1
    )
    replacements = {
        "co_name": {"co_name": huge_text},
        "co_qualname": {"co_qualname": huge_text},
        "co_filename": {"co_filename": huge_text},
        "co_code": {"co_code": huge_bytes},
        "co_linetable": {"co_linetable": huge_bytes},
        "co_exceptiontable": {"co_exceptiontable": huge_bytes},
        "co_consts": {"co_consts": (huge_text,)},
        "co_names": {"co_names": (huge_text,)},
        "co_varnames": {"co_varnames": (huge_text,)},
        "co_freevars": {"co_freevars": (huge_text,)},
        "co_cellvars": {"co_cellvars": (huge_text,)},
    }
    forged = code.replace(**replacements[field])
    with pytest.raises(W.WorkerExecutionError, match="maximum bytes"):
        _bind(forged)


def test_code_metadata_aggregate_and_nested_siblings_share_byte_budget() -> None:
    code = _sample_code()
    half = W._TRUSTED_CODE_CONSTANT_MAX_BYTES // 2
    forged = code.replace(co_name="a" * half, co_qualname="b" * half)
    with pytest.raises(W.WorkerExecutionError, match="maximum bytes"):
        _bind(forged)

    nested = code.replace(co_linetable=b"x" * half)
    forged = code.replace(co_consts=(nested, nested))
    with pytest.raises(W.WorkerExecutionError, match="maximum bytes"):
        _bind(forged)


def test_code_name_roster_elements_share_node_budget() -> None:
    code = _sample_code()
    names = ("x",) * (W._TRUSTED_CODE_CONSTANT_MAX_NODES + 1)
    forged = code.replace(co_names=names)
    with pytest.raises(W.WorkerExecutionError, match="maximum nodes"):
        _bind(forged)


def test_callback_bearing_code_metadata_subclasses_are_rejected_unobserved() -> None:
    calls: list[str] = []

    class CallbackStr(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            calls.append("encode")
            return super().encode(*args, **kwargs)

    class CallbackBytes(bytes):
        def __len__(self) -> int:
            calls.append("len")
            return super().__len__()

    code = _sample_code()
    forged_name = code.replace(co_name=CallbackStr("sample"))
    calls.clear()
    with pytest.raises(W.WorkerExecutionError, match="not an exact string"):
        _bind(forged_name)
    assert calls == []

    forged_table = code.replace(
        co_linetable=CallbackBytes(code.co_linetable)
    )
    calls.clear()
    with pytest.raises(W.WorkerExecutionError, match="not exact bytes"):
        _bind(forged_table)
    assert calls == []
