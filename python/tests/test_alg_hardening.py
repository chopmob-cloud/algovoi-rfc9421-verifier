"""Sprint A item 3: algorithm-downgrade hardening tests."""
from __future__ import annotations

from algovoi_rfc9421_verifier import verify_request
from algovoi_rfc9421_signer import sign_request

SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
PUBKEY_HEX = "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41"
AUTHORITY = "api.algovoi.co.uk"
PATH = "/compliance/attestation"
METHOD = "GET"
KEYID = "did:web:api.algovoi.co.uk"


def _sign(**kw) -> dict:
    res = sign_request(
        method=METHOD, authority=AUTHORITY, path=PATH, body=b"",
        private_key=SEED_HEX, keyid=KEYID, **kw,
    )
    return {
        "host": AUTHORITY,
        "content-digest": res.content_digest,
        "signature-input": res.signature_input,
        "signature": res.signature,
    }


def _verify(headers, **kw):
    return verify_request(
        method=METHOD, authority=AUTHORITY, path=PATH,
        headers=headers, body=b"", public_key=PUBKEY_HEX, **kw,
    )


def test_ed25519_passes():
    result = _verify(_sign())
    assert result.valid is True, result.errors


def test_absent_alg_fails():
    # Strip the alg= parameter from Signature-Input: an absent alg is a
    # downgrade-by-omission vector and must be rejected, not defaulted.
    headers = _sign()
    headers["signature-input"] = headers["signature-input"].replace(';alg="ed25519"', "")
    result = _verify(headers)
    assert result.valid is False
    assert any("alg" in e.lower() and "missing" in e.lower() for e in result.errors)


def test_disallowed_alg_fails():
    # A well-formed ed25519 signature is rejected when the caller's allow-list
    # does not include ed25519.
    result = _verify(_sign(), allowed_algorithms={"ecdsa-p256-sha256"})
    assert result.valid is False
    assert any("not in the allowed set" in e for e in result.errors)


def test_allowed_list_with_ed25519_passes():
    result = _verify(_sign(), allowed_algorithms={"ed25519", "ecdsa-p256-sha256"})
    assert result.valid is True, result.errors
