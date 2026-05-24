"""End-to-end tests using the rfc9421_proxy_chain_v0 fixture."""
from __future__ import annotations

import base64
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

# RFC 8032 Section 7.1 Test 1 deterministic reference keypair
RFC8032_TEST1_PUBKEY_HEX = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

# Fixture data from rfc9421_proxy_chain_v0 (request.fixture.json)
FIXTURE_METHOD = "GET"
FIXTURE_AUTHORITY = "api.algovoi.co.uk"
FIXTURE_PATH = "/compliance/attestation"
FIXTURE_HEADERS = {
    "host": "api.algovoi.co.uk",
    "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    "signature-input": (
        'sig=("@method" "@authority" "@path" "content-digest" "created");'
        'created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
    ),
    "signature": (
        "sig=:Xj1peMjEYi75R/QQFYpU9q/gHwQKYwgt1etjAX1qc0zugTMJoJ86Uhy/jTZ175b3"
        "zFhp0j8cLjmDJvGmySDBAQ==:"
    ),
}
FIXTURE_BODY = b""
FIXTURE_EXPECTED_SIGNING_BASE = (
    '"@method": get\n'
    '"@authority": api.algovoi.co.uk\n'
    '"@path": /compliance/attestation\n'
    '"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\n'
    '"created": 1778955520'
)


# ---------------------------------------------------------------------
# parse_signature_input
# ---------------------------------------------------------------------


def test_parse_signature_input_full():
    si = parse_signature_input(FIXTURE_HEADERS["signature-input"])
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
    """Real-world impls sometimes emit the unlabelled form; we accept
    it with label=''."""
    si = parse_signature_input('("@method" "@path");created=1')
    assert si.label == ""
    assert si.covered_components == ["@method", "@path"]
    assert si.parameters["created"] == 1


def test_parse_signature_input_garbage_raises():
    with pytest.raises(SignatureInputParseError):
        parse_signature_input("totally-garbage-input")


def test_parse_signature_value():
    label, sig_bytes = parse_signature_value(FIXTURE_HEADERS["signature"])
    assert label == "sig"
    assert len(sig_bytes) == 64


def test_parse_signature_value_no_colons_raises():
    with pytest.raises(SignatureInputParseError):
        parse_signature_value("sig=Xj1pe...")


# ---------------------------------------------------------------------
# build_signing_base
# ---------------------------------------------------------------------


def test_build_signing_base_fixture_match():
    si = parse_signature_input(FIXTURE_HEADERS["signature-input"])
    base = build_signing_base(
        si.covered_components,
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=FIXTURE_HEADERS,
        parameters=si.parameters,
    )
    assert base == FIXTURE_EXPECTED_SIGNING_BASE


def test_build_signing_base_missing_component_raises():
    with pytest.raises(Exception):  # SigningBaseError
        build_signing_base(["@method"], authority=FIXTURE_AUTHORITY)


# ---------------------------------------------------------------------
# Content-Digest
# ---------------------------------------------------------------------


def test_compute_content_digest_empty_body():
    cd = compute_content_digest(b"", "sha-256")
    assert cd == "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"


def test_compute_content_digest_nonempty():
    cd = compute_content_digest(b"hello world", "sha-256")
    assert cd.startswith("sha-256=:")


def test_verify_content_digest_empty_body():
    assert verify_content_digest(b"", FIXTURE_HEADERS["content-digest"])


def test_verify_content_digest_mismatch_raises():
    with pytest.raises(Exception):  # ContentDigestError
        verify_content_digest(b"non-empty body", FIXTURE_HEADERS["content-digest"])


# ---------------------------------------------------------------------
# verify_signature
# ---------------------------------------------------------------------


def test_verify_signature_ok():
    _, sig_bytes = parse_signature_value(FIXTURE_HEADERS["signature"])
    ok = verify_signature(
        FIXTURE_EXPECTED_SIGNING_BASE, sig_bytes, RFC8032_TEST1_PUBKEY_HEX
    )
    assert ok is True


def test_verify_signature_tampered_base_fails():
    _, sig_bytes = parse_signature_value(FIXTURE_HEADERS["signature"])
    tampered = FIXTURE_EXPECTED_SIGNING_BASE.replace("get", "post")
    ok = verify_signature(tampered, sig_bytes, RFC8032_TEST1_PUBKEY_HEX)
    assert ok is False


def test_verify_signature_wrong_key_fails():
    _, sig_bytes = parse_signature_value(FIXTURE_HEADERS["signature"])
    wrong_key = "00" * 32
    ok = verify_signature(FIXTURE_EXPECTED_SIGNING_BASE, sig_bytes, wrong_key)
    assert ok is False


# ---------------------------------------------------------------------
# verify_request (top-level)
# ---------------------------------------------------------------------


def test_verify_request_fixture_passes():
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=FIXTURE_HEADERS,
        body=FIXTURE_BODY,
        public_key=RFC8032_TEST1_PUBKEY_HEX,
    )
    assert result.valid is True
    assert result.signature_valid is True
    assert result.content_digest_valid is True
    assert result.errors == []
    assert result.signing_base == FIXTURE_EXPECTED_SIGNING_BASE
    assert result.label == "sig"


def test_verify_request_missing_signature_input():
    headers = {k: v for k, v in FIXTURE_HEADERS.items() if k != "signature-input"}
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=headers,
        body=FIXTURE_BODY,
        public_key=RFC8032_TEST1_PUBKEY_HEX,
    )
    assert result.valid is False
    assert any("Signature-Input" in e for e in result.errors)


def test_verify_request_tampered_path_fails():
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path="/different/path",
        headers=FIXTURE_HEADERS,
        body=FIXTURE_BODY,
        public_key=RFC8032_TEST1_PUBKEY_HEX,
    )
    assert result.valid is False
    assert result.signature_valid is False


def test_verify_request_non_empty_body_fails_digest():
    result = verify_request(
        method=FIXTURE_METHOD,
        authority=FIXTURE_AUTHORITY,
        path=FIXTURE_PATH,
        headers=FIXTURE_HEADERS,
        body=b"non-empty",
        public_key=RFC8032_TEST1_PUBKEY_HEX,
    )
    assert result.valid is False
    assert any("Content-Digest" in e for e in result.errors)


def test_verify_request_loads_from_real_fixture():
    """Live cross-validation against the algovoi-jcs-conformance-vectors
    rfc9421_proxy_chain_v0/request.fixture.json file -- ensures the
    library agrees with the corpus fixture byte-for-byte."""
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
    )
    assert result.valid is True
    assert result.signing_base == fixture["signing"]["signing_base"]
