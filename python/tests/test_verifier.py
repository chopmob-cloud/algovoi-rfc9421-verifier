"""End-to-end tests for algovoi-rfc9421-verifier."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from algovoi_rfc9421_verifier import (
    SignatureInputParseError,
    VerifyResult,
    build_signing_base,
    compute_content_digest,
    parse_signature_input,
    parse_signature_value,
    verify_content_digest,
    verify_request,
    verify_signature,
)

# Deterministic Ed25519 test keypair.
# Seed: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
# Public key derived by both @noble/ed25519 and PyNaCl from that seed.
# Matches the SEED_HEX constant in algovoi-rfc9421-signer tests.
PUBKEY_HEX = "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41"

FIXTURE_METHOD = "GET"
FIXTURE_AUTHORITY = "api.algovoi.co.uk"
FIXTURE_PATH = "/compliance/attestation"
FIXTURE_BODY = b""

# ---------------------------------------------------------------------------
# algovoi-v0 fixture: @method lowercased, no @signature-params line.
# Kept for backward-compatibility testing of mode="algovoi-v0".
# ---------------------------------------------------------------------------

FIXTURE_HEADERS_V0 = {
    "host": "api.algovoi.co.uk",
    "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    "signature-input": (
        'sig=("@method" "@authority" "@path" "content-digest" "created");'
        'created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
    ),
    "signature": (
        "sig=:WHJ5F5rw3TF+DuufgkEa+XNgD5KnoMPNGAMoj/7Zkpbx4sSKNn4SyFh1qiBNnRQG"
        "tfvaEdpNyYo0xRK6HBS0Bw==:"
    ),
}

FIXTURE_SIGNING_BASE_V0 = (
    '"@method": get\n'
    '"@authority": api.algovoi.co.uk\n'
    '"@path": /compliance/attestation\n'
    '"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\n'
    '"created": 1778955520'
)

# ---------------------------------------------------------------------------
# RFC 9421 fixture (v0.2.0+ default): @method case-preserved,
# @signature-params line appended. Matches algovoi-rfc9421-signer output.
# ---------------------------------------------------------------------------

FIXTURE_HEADERS_RFC9421 = {
    "host": "api.algovoi.co.uk",
    "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    "signature-input": (
        'sig=("@method" "@authority" "@path" "content-digest" "created");'
        'created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
    ),
    "signature": (
        "sig=:JZ3cN4Gl8h5s2635bQ6/bczGo+e9acNWxVbR4XhqQiBrFteh71trVrGbBJUkw7v1"
        "NVv1GlpVEZMvvKXYGPuLBQ==:"
    ),
}

FIXTURE_SIGNING_BASE_RFC9421 = (
    '"@method": GET\n'
    '"@authority": api.algovoi.co.uk\n'
    '"@path": /compliance/attestation\n'
    '"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\n'
    '"created": 1778955520\n'
    '"@signature-params": ("@method" "@authority" "@path" "content-digest" "created")'
    ';created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
)


# ---------------------------------------------------------------------------
# parse_signature_input
# ---------------------------------------------------------------------------


def test_parse_signature_input_full():
    si = parse_signature_input(FIXTURE_HEADERS_V0["signature-input"])
    assert si.label == "sig"
    assert si.covered_components == [
        "@method", "@authority", "@path", "content-digest", "created",
    ]
    assert si.parameters["created"] == 1778955520
    assert si.parameters["keyid"] == "did:web:api.algovoi.co.uk"
    assert si.parameters["alg"] == "ed25519"


def test_parse_signature_input_empty_raises():
    with pytest.raises(SignatureInputParseError):
        parse_signature_input("")


def test_parse_signature_input_unlabelled_accepted():
    si = parse_signature_input('("@method" "@path");created=1')
    assert si.label == ""
    assert si.covered_components == ["@method", "@path"]
    assert si.parameters["created"] == 1


def test_parse_signature_input_garbage_raises():
    with pytest.raises(SignatureInputParseError):
        parse_signature_input("totally-garbage-input")


def test_parse_signature_value():
    label, sig_bytes = parse_signature_value(FIXTURE_HEADERS_V0["signature"])
    assert label == "sig"
    assert len(sig_bytes) == 64


def test_parse_signature_value_no_colons_raises():
    with pytest.raises(SignatureInputParseError):
        parse_signature_value("sig=Xj1pe...")


# ---------------------------------------------------------------------------
# build_signing_base
# ---------------------------------------------------------------------------


def test_build_signing_base_v0_fixture_match():
    si = parse_signature_input(FIXTURE_HEADERS_V0["signature-input"])
    base = build_signing_base(
        si.covered_components,
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=FIXTURE_HEADERS_V0,
        parameters=si.parameters,
        mode="algovoi-v0",
    )
    assert base == FIXTURE_SIGNING_BASE_V0


def test_build_signing_base_rfc9421_fixture_match():
    si = parse_signature_input(FIXTURE_HEADERS_RFC9421["signature-input"])
    base = build_signing_base(
        si.covered_components,
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=FIXTURE_HEADERS_RFC9421,
        parameters=si.parameters,
        mode="rfc9421",
        signature_params_raw=si.params_block,
    )
    assert base == FIXTURE_SIGNING_BASE_RFC9421


def test_build_signing_base_missing_component_raises():
    with pytest.raises(Exception):
        build_signing_base(["@method"], authority=FIXTURE_AUTHORITY)


# ---------------------------------------------------------------------------
# Content-Digest
# ---------------------------------------------------------------------------


def test_compute_content_digest_empty_body():
    cd = compute_content_digest(b"", "sha-256")
    assert cd == "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"


def test_compute_content_digest_nonempty():
    cd = compute_content_digest(b"hello world", "sha-256")
    assert cd.startswith("sha-256=:")


def test_verify_content_digest_empty_body():
    assert verify_content_digest(b"", FIXTURE_HEADERS_V0["content-digest"])


def test_verify_content_digest_mismatch_raises():
    with pytest.raises(Exception):
        verify_content_digest(b"non-empty body", FIXTURE_HEADERS_V0["content-digest"])


# ---------------------------------------------------------------------------
# verify_signature
# ---------------------------------------------------------------------------


def test_verify_signature_v0_ok():
    _, sig_bytes = parse_signature_value(FIXTURE_HEADERS_V0["signature"])
    ok = verify_signature(FIXTURE_SIGNING_BASE_V0, sig_bytes, PUBKEY_HEX)
    assert ok is True


def test_verify_signature_rfc9421_ok():
    _, sig_bytes = parse_signature_value(FIXTURE_HEADERS_RFC9421["signature"])
    ok = verify_signature(FIXTURE_SIGNING_BASE_RFC9421, sig_bytes, PUBKEY_HEX)
    assert ok is True


def test_verify_signature_tampered_base_fails():
    _, sig_bytes = parse_signature_value(FIXTURE_HEADERS_V0["signature"])
    tampered = FIXTURE_SIGNING_BASE_V0.replace("get", "post")
    ok = verify_signature(tampered, sig_bytes, PUBKEY_HEX)
    assert ok is False


def test_verify_signature_wrong_key_fails():
    _, sig_bytes = parse_signature_value(FIXTURE_HEADERS_V0["signature"])
    wrong_key = "00" * 32
    ok = verify_signature(FIXTURE_SIGNING_BASE_V0, sig_bytes, wrong_key)
    assert ok is False


# ---------------------------------------------------------------------------
# verify_request — default mode is rfc9421 (v0.3.0+)
# ---------------------------------------------------------------------------


def test_verify_request_rfc9421_default_passes():
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=FIXTURE_HEADERS_RFC9421,
        body=FIXTURE_BODY,
        public_key=PUBKEY_HEX,
    )
    assert result.valid is True
    assert result.signature_valid is True
    assert result.content_digest_valid is True
    assert result.errors == []
    assert result.signing_base == FIXTURE_SIGNING_BASE_RFC9421
    assert result.label == "sig"


def test_verify_request_algovoi_v0_explicit_passes():
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=FIXTURE_HEADERS_V0,
        body=FIXTURE_BODY,
        public_key=PUBKEY_HEX,
        mode="algovoi-v0",
    )
    assert result.valid is True
    assert result.signing_base == FIXTURE_SIGNING_BASE_V0


def test_verify_request_missing_signature_input():
    headers = {k: v for k, v in FIXTURE_HEADERS_RFC9421.items() if k != "signature-input"}
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=headers,
        body=FIXTURE_BODY,
        public_key=PUBKEY_HEX,
    )
    assert result.valid is False
    assert any("Signature-Input" in e for e in result.errors)


def test_verify_request_tampered_path_fails():
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path="/different/path",
        headers=FIXTURE_HEADERS_RFC9421,
        body=FIXTURE_BODY,
        public_key=PUBKEY_HEX,
    )
    assert result.valid is False
    assert result.signature_valid is False


def test_verify_request_non_empty_body_fails_digest():
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=FIXTURE_HEADERS_RFC9421,
        body=b"non-empty",
        public_key=PUBKEY_HEX,
    )
    assert result.valid is False
    assert any("Content-Digest" in e for e in result.errors)


def test_verify_request_loads_from_real_fixture():
    """Live cross-validation against the algovoi-jcs-conformance-vectors
    rfc9421_proxy_chain_v0/request.fixture.json file."""
    fixture_path = Path(
        r"C:\algo\algovoi-jcs-conformance-vectors\vectors\rfc9421_proxy_chain_v0\request.fixture.json"
    )
    if not fixture_path.exists():
        pytest.skip(f"corpus fixture not present at {fixture_path}")
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    req = fixture["request"]
    result = verify_request(
        method=req["method"],
        authority=req["authority"],
        path=req["path"],
        headers=req["headers"],
        body=b"",
        public_key=fixture["keypair"]["public_key_hex"],
        mode="algovoi-v0",
    )
    assert result.valid is True
    assert result.signing_base == fixture["signing"]["signing_base"]
