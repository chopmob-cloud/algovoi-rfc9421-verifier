"""Tests for the Ed25519 public-key trust-boundary gate (keycheck).

Correctness of small-order detection is mathematical ([8]P == identity), so these
tests exercise the gate against known small-order encodings, non-canonical
encodings, and a large sample of valid keys — and confirm the gate fails closed
end-to-end through verify_request.
"""
import pytest
from nacl.signing import SigningKey

from algovoi_rfc9421_verifier.keycheck import (
    WeakKeyError,
    check_ed25519_public_key,
    is_small_order,
)

# Small-order encodings (little-endian, 32 bytes) covering orders 1, 2, 4.
# The gate is order-agnostic (rejects any point with [8]P == identity); these
# anchor the well-known cases.
IDENTITY        = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")  # (0,1)  order 1
ORDER2_NEG1     = bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")  # y=p-1  order 2
ORDER4_YZERO    = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")  # y=0    order 4
ORDER4_YZERO_HI = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080")  # y=0, sign bit
SMALL_ORDER = [IDENTITY, ORDER2_NEG1, ORDER4_YZERO, ORDER4_YZERO_HI]

# Non-canonical: y == p (>= p). Must be rejected as non-canonical/off-curve.
NONCANONICAL_Y_EQ_P = bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

# RFC 8032 Section 7.1 Test 1 public key — a valid large-order point.
RFC8032_TEST1_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


@pytest.mark.parametrize("pk", SMALL_ORDER)
def test_small_order_detected(pk):
    assert is_small_order(pk) is True
    with pytest.raises(WeakKeyError):
        check_ed25519_public_key(pk)


def test_noncanonical_rejected():
    with pytest.raises(WeakKeyError):
        check_ed25519_public_key(NONCANONICAL_Y_EQ_P)


def test_wrong_length_rejected():
    with pytest.raises(WeakKeyError):
        check_ed25519_public_key(b"\x01" * 31)


def test_rfc8032_test1_key_accepted():
    check_ed25519_public_key(RFC8032_TEST1_PUB)  # must not raise
    assert is_small_order(RFC8032_TEST1_PUB) is False


def test_many_valid_keys_accepted():
    # A large sample of genuine keypairs must all pass and none be flagged small-order.
    for i in range(200):
        pk = SigningKey(bytes([i % 256]) * 32).verify_key.encode()
        check_ed25519_public_key(pk)
        assert is_small_order(pk) is False


def test_verify_request_fails_closed_on_small_order_key():
    # End-to-end: a small-order public key must make verify_request fail (not raise,
    # not pass), before/independent of signature checking.
    from algovoi_rfc9421_verifier import verify_request

    result = verify_request(
        method="POST",
        authority="api.algovoi.co.uk",
        path="/a2a",
        headers={
            "signature-input": 'sig=("@method");created=1750000000;keyid="k";alg="ed25519"',
            "signature": "sig=:" + "A" * 86 + "==:",
            "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
        },
        body=b"",
        public_key=IDENTITY,
        require_content_digest=False,
    )
    assert result.valid is False
    assert any("small-order" in e or "canonical" in e for e in result.errors)
