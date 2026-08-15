"""RC-1: required covered-component policy tests.

verify_request(required_components=[...]) lets a caller demand that specific
components (typically @method/@authority/@path) are actually covered by the
signature. A cryptographically valid signature over a narrow covered set is
rejected when it omits a required component, closing the request-line-rewrite
gap.
"""
from __future__ import annotations

from algovoi_rfc9421_verifier import verify_request

PUBKEY_HEX = "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41"
AUTHORITY = "api.algovoi.co.uk"
PATH = "/compliance/attestation"
CD = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
# Valid RFC 9421 fixture (covers @method/@authority/@path/content-digest/created).
FULL_HEADERS = {
    "host": AUTHORITY,
    "content-digest": CD,
    "signature-input": (
        'sig=("@method" "@authority" "@path" "content-digest" "created");'
        'created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
    ),
    "signature": (
        "sig=:JZ3cN4Gl8h5s2635bQ6/bczGo+e9acNWxVbR4XhqQiBrFteh71trVrGbBJUkw7v1"
        "NVv1GlpVEZMvvKXYGPuLBQ==:"
    ),
}
# Same signer/params but a narrow covered set omitting @authority and @path.
NARROW_HEADERS = {
    "host": AUTHORITY,
    "content-digest": CD,
    "signature-input": (
        'sig=("@method" "content-digest" "created");'
        'created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
    ),
    "signature": FULL_HEADERS["signature"],
}


def _verify(headers, **kw):
    return verify_request(
        method="GET", authority=AUTHORITY, path=PATH,
        headers=headers, body=b"", public_key=PUBKEY_HEX,
        now=1778955600, **kw,
    )


def test_required_components_present_passes():
    result = _verify(FULL_HEADERS, required_components=["@method", "@authority", "@path"])
    assert result.valid is True, result.errors


def test_required_component_missing_rejected():
    result = _verify(NARROW_HEADERS, required_components=["@method", "@authority", "@path"])
    assert result.valid is False
    assert any("required covered components missing" in e for e in result.errors)


def test_no_policy_does_not_reject_for_coverage():
    # Without the policy the narrow signature is not rejected for coverage; any
    # failure would be at signature/content-digest, never a required-components error.
    result = _verify(NARROW_HEADERS)
    assert not any("required covered components missing" in e for e in result.errors)
