from __future__ import annotations
import hashlib
import json
import pytest
import runtime_policy_artifacts as A

PATHS = {"forge": "/usr/local/bin/forge", "worker": "/opt/plamen/worker.py"}

def canonical(v):
    return (json.dumps(v, sort_keys=True, separators=(",", ":")) + "\n").encode()

def census():
    rows = []
    for index, path in enumerate(sorted(p.removeprefix("/") for p in PATHS.values())):
        rows.append({"kind":"file","linkname":"","mode":"0555","path":path,
                     "sha256":hashlib.sha256(path.encode()).hexdigest(),"size":index+1})
    return canonical({"entries": rows, "schema_version": A.INSTALLED_CENSUS_SCHEMA})

def test_exact_deterministic_projection_and_replay():
    raw = census(); first = A.render_baked_image_member_closure(raw, required_paths=PATHS)
    assert first == A.render_baked_image_member_closure(raw, required_paths=PATHS)
    assert A.validate_baked_image_member_closure(first, raw, required_paths=PATHS)["members"]

@pytest.mark.parametrize("mutation", ["missing", "symlink", "digest", "size", "order"])
def test_invalid_or_incomplete_census_refuses(mutation):
    value = json.loads(census()); rows = value["entries"]
    if mutation == "missing": rows.pop()
    elif mutation == "symlink": rows[0].update(kind="symlink", linkname="target", sha256=None, size=0)
    elif mutation == "digest": rows[0]["sha256"] = "0" * 64
    elif mutation == "size": rows[0]["size"] = True
    else: rows.reverse()
    with pytest.raises(A.RuntimePolicyArtifactError):
        A.render_baked_image_member_closure(canonical(value), required_paths=PATHS)

def test_artifact_tamper_and_noncanonical_census_refuse():
    raw = census(); closure = A.render_baked_image_member_closure(raw, required_paths=PATHS)
    with pytest.raises(A.RuntimePolicyArtifactError):
        A.validate_baked_image_member_closure(closure[:-2] + b"x\n", raw, required_paths=PATHS)
    with pytest.raises(A.RuntimePolicyArtifactError):
        A.render_baked_image_member_closure(json.dumps(json.loads(raw)).encode(), required_paths=PATHS)

def test_seccomp_profile_has_exact_documented_network_denominator():
    raw = A.render_linux_guest_seccomp_profile()
    value = A.validate_linux_guest_seccomp_profile(raw)
    assert tuple(value["syscalls"][0]["names"]) == A.BLOCKED_NETWORK_ADMIN_SYSCALLS
    assert [row["args"][0] for row in value["syscalls"][1:]] == [
        {"index":0,"op":"SCMP_CMP_MASKED_EQ","value":0xffffffff,"valueTwo":16},
        {"index":0,"op":"SCMP_CMP_MASKED_EQ","value":0xffffffff,"valueTwo":17},
        {"index":1,"op":"SCMP_CMP_MASKED_EQ","value":15,"valueTwo":3},
    ]
    assert value["architectures"] == ["SCMP_ARCH_AARCH64"]

def test_seccomp_profile_refuses_any_byte_or_rule_change():
    raw = A.render_linux_guest_seccomp_profile()
    with pytest.raises(A.RuntimePolicyArtifactError):
        A.validate_linux_guest_seccomp_profile(raw.replace(b'"bpf"', b'"keyctl"'))

def test_socket_int_arguments_cannot_bypass_with_high_words_or_type_flags():
    rules = A.validate_linux_guest_seccomp_profile(
        A.render_linux_guest_seccomp_profile())["syscalls"][1:]
    def matches(rule, argument):
        arg = rule["args"][0]
        return argument & arg["value"] == arg["valueTwo"]
    for family in (16, 17):
        rule = rules[family - 16]
        assert matches(rule, family)
        assert matches(rule, (0xdeadbeef << 32) | family)
        assert not matches(rule, family + 2)
    raw_rule = rules[2]
    assert matches(raw_rule, 3)
    assert matches(raw_rule, 3 | 0x80000 | 0x800)
    assert not matches(raw_rule, 2 | 0x80000)
