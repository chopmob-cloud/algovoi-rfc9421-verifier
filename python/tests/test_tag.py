"""Sprint A item 2: RFC 9421 `tag` anti cross-protocol reuse tests."""
from __future__ import annotations

from algovoi_rfc9421_verifier import verify_request
from algovoi_rfc9421_signer import sign_request

SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
PUBKEY_HEX = "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41"
AUTHORITY = "api.algovoi.co.uk"
PATH = "/compliance/attestation"
METHOD = "GET"
KEYID = "did:web:api.algovoi.co.uk"
TAG = "algovoi-a2a-v1"


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


def test_matching_tag_passes():
    headers = _sign(tag=TAG)
    result = _verify(headers, expected_tag=TAG)
    assert result.valid is True, result.errors
    assert result.parameters.get("tag") == TAG


def test_wrong_tag_fails():
    headers = _sign(tag=TAG)
    result = _verify(headers, expected_tag="some-other-context")
    assert result.valid is False
    assert any("tag" in e.lower() for e in result.errors)


def test_missing_tag_fails_when_required():
    headers = _sign()  # no tag emitted
    result = _verify(headers, require_tag=True)
    assert result.valid is False
    assert any("tag" in e.lower() for e in result.errors)


def test_missing_tag_ignored_when_not_required():
    headers = _sign()
    result = _verify(headers)  # no tag policy
    assert result.valid is True, result.errors


def test_signer_emits_bound_tag():
    # The tag rides inside @signature-params, so altering it on the wire must
    # break the signature (proves it is cryptographically bound, not advisory).
    headers = _sign(tag=TAG)
    tampered = dict(headers)
    tampered["signature-input"] = headers["signature-input"].replace(
        f'tag="{TAG}"', 'tag="attacker-swapped"'
    )
    result = _verify(tampered, expected_tag="attacker-swapped")
    assert result.valid is False
    assert result.signature_valid is False
