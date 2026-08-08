"""Ed25519 public-key validation for the verifier's trust boundary.

Rejects, fail-closed and *before* signature verification:

  1. non-canonical encodings  (y-coordinate >= p, i.e. a duplicate encoding of a
     valid point -- a malleability class), and points not on the curve;
  2. small-order points        (order dividing the cofactor 8, incl. the identity),
     which permit signature-malleability / cross-key verification classes.

Why this is needed: PyNaCl / libsodium's basic `crypto_sign_verify` and
@noble/ed25519 under its default ZIP215 rules both ACCEPT small-order (and some
non-canonical) public keys. For an audited offline verifier that treats the
resolved key as the trust anchor, accepting such a key is a defect. This gate is
self-contained (RFC 8032 Appendix A arithmetic, extended homogeneous coords) and
derives small-order-ness mathematically ([8]P == identity) rather than trusting a
hard-coded blocklist.
"""
from __future__ import annotations

_p = 2**255 - 19
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


class WeakKeyError(ValueError):
    """Raised when an Ed25519 public key is non-canonical, off-curve, or small-order."""


def _recover_x(y: int, sign: int):
    if y >= _p:
        return None  # non-canonical y encoding
    x2 = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None  # not a square -> point not on curve
    if (x & 1) != sign:
        x = _p - x
    return x


def _decode(pk: bytes):
    """Decode a 32-byte Ed25519 public key to extended coords, or None if invalid."""
    if len(pk) != 32:
        return None
    y = int.from_bytes(pk, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul8(P):
    return _add(_add(_add(P, P), _add(P, P)), _add(_add(P, P), _add(P, P)))


def _is_identity(P) -> bool:
    # affine (0, 1): X/Z == 0 and Y/Z == 1  <=>  X == 0 and Y == Z (mod p)
    return P[0] % _p == 0 and (P[1] - P[2]) % _p == 0


def is_small_order(pk: bytes) -> bool:
    """True iff pk decodes to a point whose order divides 8 (incl. identity).

    Returns False for keys that fail to decode (handled by check_ed25519_public_key).
    """
    P = _decode(pk)
    if P is None:
        return False
    return _is_identity(_mul8(P))


def check_ed25519_public_key(pk: bytes) -> None:
    """Raise WeakKeyError if pk is non-canonical, off-curve, or small-order.

    Returns None for a canonical, on-curve, large-order public key.
    """
    P = _decode(pk)
    if P is None:
        raise WeakKeyError("public key is not a canonical on-curve Ed25519 point")
    if _is_identity(_mul8(P)):
        raise WeakKeyError("public key is a small-order Ed25519 point")


__all__ = ["WeakKeyError", "check_ed25519_public_key", "is_small_order"]
