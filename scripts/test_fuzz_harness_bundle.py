from __future__ import annotations

from pathlib import Path

import pytest

import fuzz_harness_bundle as F


def _invariant_bundle(source: str = "contract InvariantFuzz {}") -> bytes:
    return f"""# Invariant Fuzz Results

## Driver Fuzz Harness Bundle

### Generated File: `test/invariant/InvariantFuzz.t.sol`
```solidity
{source}
```

## Driver Fuzz Campaign

**Tool**: forge
**CWD**: .
**Arguments JSON**: ["forge","test","--match-contract","InvariantFuzz","-vv"]
**Assertions JSON**: ["INV-1"]
**Expected Cases**: 6400

<!-- PLAMEN_STATUS: COMPLETE -->
""".encode()


def test_parse_and_compare_only_materialize(tmp_path: Path) -> None:
    active = tmp_path / "active"
    active.mkdir()
    bundle = F.parse_fuzz_harness_bundle(
        _invariant_bundle(), role="invariant_fuzz"
    )
    manifest = F.materialize_fuzz_harness_bundle(bundle, active_root=active)
    assert (active / "test/invariant/InvariantFuzz.t.sol").read_text() == (
        "contract InvariantFuzz {}\n"
    )
    assert manifest.is_file()
    # Driver resume is compare-only and does not rewrite admitted bytes.
    before = manifest.stat().st_mtime_ns
    assert F.materialize_fuzz_harness_bundle(bundle, active_root=active) == manifest
    assert manifest.stat().st_mtime_ns == before


def test_invariant_proxy_variable_cast_is_projected_without_changing_assertions() -> None:
    source = (
        'string constant bait = "TargetGateway(address(proxy))";\n'
        "// TargetGateway(address(proxy)) must remain a comment\n"
        "contract InvariantFuzz {\n"
        "  function setUp() public {\n"
        "    TargetGateway target = TargetGateway(address(proxy));\n"
        "    require(address(target) != address(0), \"assertion\");\n"
        "  }\n"
        "}\n"
    )
    bundle = F.parse_fuzz_harness_bundle(
        _invariant_bundle(source), role="invariant_fuzz"
    )
    solidity = bundle.files[0]
    effective = solidity.content.decode()
    assert "TargetGateway(payable(address(proxy)))" in effective
    assert '"TargetGateway(address(proxy))"' in effective
    assert "// TargetGateway(address(proxy))" in effective
    assert 'require(address(target) != address(0), "assertion")' in effective
    assert solidity.source_sha256 != solidity.sha256
    assert solidity.projection == "DRIVER_PAYABLE_PROXY_VARIABLE_CAST_V1"

    replay = F.parse_fuzz_harness_bundle(
        _invariant_bundle(effective), role="invariant_fuzz"
    )
    assert replay.files[0].content.rstrip() == solidity.content.rstrip()
    assert replay.files[0].projection == "IDENTITY"


def test_parser_accepts_prompt_canonical_heading_without_colon() -> None:
    raw = _invariant_bundle().replace(
        b"### Generated File: `test/invariant/InvariantFuzz.t.sol`",
        b"### Generated File `test/invariant/InvariantFuzz.t.sol`",
    )
    bundle = F.parse_fuzz_harness_bundle(raw, role="invariant_fuzz")
    assert [row.relative_path for row in bundle.files] == [
        "test/invariant/InvariantFuzz.t.sol"
    ]


def test_parser_rejects_obsolete_forge_invariant_flags() -> None:
    raw = _invariant_bundle().replace(
        b'["forge","test","--match-contract","InvariantFuzz","-vv"]',
        b'["forge","test","--match-contract","InvariantFuzz",'
        b'"--invariant-runs","256","--invariant-depth","25","-vv"]',
    )
    with pytest.raises(F.FuzzHarnessBundleError, match="assigned fuzz campaign"):
        F.parse_fuzz_harness_bundle(raw, role="invariant_fuzz")


@pytest.mark.parametrize(
    "changed",
    [
        "../Escape.t.sol",
        "/tmp/Escape.t.sol",
        "test\\invariant\\Escape.t.sol",
        "contracts/Escape.t.sol",
    ],
)
def test_invariant_bundle_rejects_path_escape_or_wrong_lane(changed: str) -> None:
    raw = _invariant_bundle().replace(
        b"test/invariant/InvariantFuzz.t.sol", changed.encode()
    )
    with pytest.raises(F.FuzzHarnessBundleError):
        F.parse_fuzz_harness_bundle(raw, role="invariant_fuzz")


def test_duplicate_alias_is_rejected() -> None:
    raw = _invariant_bundle().replace(
        b"## Driver Fuzz Campaign",
        b"""### Generated File: `TEST/invariant/InvariantFuzz.t.sol`
```solidity
contract Other {}
```

## Driver Fuzz Campaign""",
    )
    with pytest.raises(F.FuzzHarnessBundleError, match="duplicate/aliased"):
        F.parse_fuzz_harness_bundle(raw, role="invariant_fuzz")


def test_materializer_rejects_conflicting_existing_file(tmp_path: Path) -> None:
    active = tmp_path / "active"
    target = active / "test/invariant/InvariantFuzz.t.sol"
    target.parent.mkdir(parents=True)
    target.write_text("different\n")
    bundle = F.parse_fuzz_harness_bundle(
        _invariant_bundle(), role="invariant_fuzz"
    )
    with pytest.raises(F.FuzzHarnessBundleError, match="drifted"):
        F.materialize_fuzz_harness_bundle(bundle, active_root=active)


def test_medusa_bundle_requires_generated_lane_and_json() -> None:
    raw = b"""# Medusa

## Driver Fuzz Harness Bundle

### Generated File: `.medusa-tests/MedusaFuzz.sol`
```solidity
contract MedusaFuzz {
    function property_example() public view returns (bool) { return true; }
}
```

### Generated File: `.medusa-tests/medusa.json`
```json
{"fuzzing":{"testLimit":50000}}
```

## Driver Fuzz Campaign

**Tool**: medusa
**CWD**: .
**Arguments JSON**: ["medusa","fuzz","--config",".medusa-tests/medusa.json","--timeout","600","--test-limit","50000"]
**Assertions JSON**: ["MEDUSA-INV-1::property_example"]
**Expected Cases**: 50000
"""
    bundle = F.parse_fuzz_harness_bundle(raw, role="medusa_fuzz")
    assert len(bundle.files) == 2
    assert bundle.tool == "medusa"
    config = next(
        row for row in bundle.files
        if row.relative_path == ".medusa-tests/medusa.json"
    )
    projected = __import__("json").loads(config.content)
    assert projected["compilation"] == {
        "platform": "crytic-compile",
        "platformConfig": {"target": "."},
    }
    assert projected["fuzzing"]["targetContracts"] == ["MedusaFuzz"]
    testing = projected["fuzzing"]["testing"]
    assert testing["propertyTesting"] == {
        "enabled": True,
        "testPrefixes": ["property_"],
    }
    assert testing["assertionTesting"] == {"enabled": True}
    assert testing["testViewMethods"] is True
    assert testing["stopOnNoTests"] is True
    assert testing["stopOnFailedTest"] is False
    assert config.projection == "DRIVER_MEDUSA_FOUNDRY_ROOT_V1"
    assert config.source_sha256 != config.sha256


def test_medusa_file_target_is_projected_to_framework_root() -> None:
    raw = b"""# Medusa

## Driver Fuzz Harness Bundle

### Generated File: `.medusa-tests/MedusaFuzzV1.sol`
```solidity
contract MedusaFuzzV1 {
    function property_feeBound() external pure returns (bool) { return true; }
}
```

### Generated File: `.medusa-tests/medusa.json`
```json
{"fuzzing":{"testLimit":50000,"targetContracts":["MedusaFuzzV1"]},"compilation":{"platform":"crytic-compile","platformConfig":{"target":".medusa-tests/MedusaFuzzV1.sol"}}}
```

## Driver Fuzz Campaign

**Tool**: medusa
**CWD**: .
**Arguments JSON**: ["medusa","fuzz","--config",".medusa-tests/medusa.json","--timeout","600","--test-limit","50000"]
**Assertions JSON**: ["MEDUSA-INV-1::property_feeBound"]
**Expected Cases**: 50000
"""
    bundle = F.parse_fuzz_harness_bundle(raw, role="medusa_fuzz")
    config = next(
        row for row in bundle.files
        if row.relative_path == ".medusa-tests/medusa.json"
    )
    projected = __import__("json").loads(config.content)
    assert projected["compilation"]["platformConfig"]["target"] == "."
    assert projected["fuzzing"]["targetContracts"] == ["MedusaFuzzV1"]


def test_medusa_proxy_contract_cast_is_projected_through_payable_address() -> None:
    raw = _medusa_bundle(
        "Gateway target;\n"
        "constructor() { target = Gateway(address(new ERC1967Proxy(address(1), hex\"\"))); }\n"
        "function property_bound() public view returns (bool) { return address(target) != address(0); }",
        '["MEDUSA-INV-1::property_bound"]',
    )
    bundle = F.parse_fuzz_harness_bundle(raw, role="medusa_fuzz")
    solidity = next(row for row in bundle.files if row.relative_path.endswith(".sol"))
    text = solidity.content.decode()
    assert (
        'Gateway(payable(address(new ERC1967Proxy(address(1), hex""))))'
        in text
    )
    assert solidity.projection == "DRIVER_MEDUSA_PAYABLE_PROXY_CAST_V1"
    assert solidity.source_sha256 != solidity.sha256


def test_medusa_payable_proxy_projection_is_narrow_and_idempotent() -> None:
    raw = _medusa_bundle(
        'string constant bait = "Gateway(address(new ERC1967Proxy()))";\n'
        "Gateway target;\n"
        "constructor() { target = Gateway(payable(address(new ERC1967Proxy(address(1), hex\"\")))); }\n"
        "function property_bound() public view returns (bool) { return address(target) != address(0); }",
        '["MEDUSA-INV-1::property_bound"]',
    )
    bundle = F.parse_fuzz_harness_bundle(raw, role="medusa_fuzz")
    solidity = next(row for row in bundle.files if row.relative_path.endswith(".sol"))
    text = solidity.content.decode()
    assert text.count("payable(address(new ERC1967Proxy") == 1
    assert '"Gateway(address(new ERC1967Proxy()))"' in text
    assert solidity.projection == "IDENTITY"


def _medusa_bundle(function: str, assertions: str) -> bytes:
    return f"""# Medusa

## Driver Fuzz Harness Bundle

### Generated File: `.medusa-tests/MedusaOracle.sol`
```solidity
contract MedusaOracle {{
    {function}
}}
```

### Generated File: `.medusa-tests/medusa.json`
```json
{{"fuzzing":{{"testLimit":50000,"targetContracts":["MedusaOracle"]}}}}
```

## Driver Fuzz Campaign

**Tool**: medusa
**CWD**: .
**Arguments JSON**: ["medusa","fuzz","--config",".medusa-tests/medusa.json","--timeout","600","--test-limit","50000"]
**Assertions JSON**: {assertions}
**Expected Cases**: 50000
""".encode()


@pytest.mark.parametrize(
    ("function", "assertions", "expected"),
    [
        (
            "function fuzz_falseIgnored() public view returns (bool) "
            "{ return false; }",
            '["MEDUSA-INV-1::fuzz_falseIgnored"]',
            "no property_ boolean property function",
        ),
        (
            "function property_hasArgument(uint256 x) public view "
            "returns (bool) { return x == 0; }",
            '["MEDUSA-INV-1::property_hasArgument"]',
            "property arguments must be empty",
        ),
        (
            "function property_mutates() public returns (bool) { return true; }",
            '["MEDUSA-INV-1::property_mutates"]',
            "must be view or pure",
        ),
        (
            "function property_wrongReturn() public view returns (uint256) "
            "{ return 1; }",
            '["MEDUSA-INV-1::property_wrongReturn"]',
            "must return exactly one bool",
        ),
        (
            "function property_bound() public view returns (bool) "
            "{ return true; }",
            '["MEDUSA-INV-1"]',
            "must name exactly one property function",
        ),
    ],
)
def test_medusa_bundle_rejects_unbound_property_oracle(
    function: str, assertions: str, expected: str,
) -> None:
    with pytest.raises(F.FuzzHarnessBundleError, match=expected):
        F.parse_fuzz_harness_bundle(
            _medusa_bundle(function, assertions), role="medusa_fuzz"
        )


def test_medusa_property_detection_ignores_comments_and_strings() -> None:
    raw = _medusa_bundle(
        'string constant bait = "function property_fake() public view '
        'returns (bool)"; // function property_comment() public view returns (bool)\n'
        "function fuzz_real() public view returns (bool) { return false; }",
        '["MEDUSA-INV-1::property_fake"]',
    )
    with pytest.raises(F.FuzzHarnessBundleError, match="no property_"):
        F.parse_fuzz_harness_bundle(raw, role="medusa_fuzz")
