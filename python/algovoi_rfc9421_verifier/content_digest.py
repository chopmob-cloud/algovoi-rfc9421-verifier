"""
RFC 9530 Content-Digest field implementation.

The Content-Digest header carries one or more digests of the message
body, each labelled by algorithm:

    Content-Digest: sha-256=:<base64>:, sha-512=:<base64>:

Per RFC 9530, the digest is computed over the message body bytes
verbatim, NOT over the canonicalised form. An empty body produces the
SHA-256 of zero bytes (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`),
base64-encoded to `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`.

This v0.1.0 implementation supports SHA-256 (mandatory per RFC 9530)
and SHA-512 (recommended). Other algorithms in the IANA registry are
roadmap.
"""

from __future__ import annotations

import base64
import hashlib
import re


class ContentDigestError(ValueError):
    """Raised when content-digest verification fails."""


_DIGEST_ENTRY_RE = re.compile(
    r'([a-z0-9-]+)=:([A-Za-z0-9+/=]+):',
)

_SUPPORTED_ALGOS = {
    "sha-256": hashlib.sha256,
    "sha-512": hashlib.sha512,
}


def compute_content_digest(body: bytes, algorithm: str = "sha-256") -> str:
    """Compute the Content-Digest header value for a body.

    Returns the structured-fields representation:
        sha-256=:<base64>:

    Multiple algorithms can be concatenated with ", " separator if
    needed (callers do that).
    """
    if not isinstance(body, (bytes, bytearray)):
        raise ContentDigestError(
            f"body must be bytes-like, got {type(body).__name__}"
        )
    algo_lower = algorithm.lower()
    if algo_lower not in _SUPPORTED_ALGOS:
        raise ContentDigestError(
            f"unsupported algorithm {algorithm!r}; supported: {sorted(_SUPPORTED_ALGOS)}"
        )
    digest = _SUPPORTED_ALGOS[algo_lower](bytes(body)).digest()
    digest_b64 = base64.b64encode(digest).decode("ascii")
    return f"{algo_lower}=:{digest_b64}:"


def verify_content_digest(
    body: bytes, header_value: str, *, require_algorithm: str | None = None
) -> bool:
    """Verify that the Content-Digest header matches the body.

    If require_algorithm is set, at least one entry in the header must
    use that algorithm and verify. Otherwise, every recognized entry
    must verify.

    Returns True if all checks pass. Raises ContentDigestError on
    malformed header or hash mismatch.
    """
    if not isinstance(header_value, str):
        raise ContentDigestError(
            f"header must be str, got {type(header_value).__name__}"
        )
    entries = _DIGEST_ENTRY_RE.findall(header_value)
    if not entries:
        raise ContentDigestError(
            f"no valid digest entries in header: {header_value!r}"
        )

    required_alg = require_algorithm.lower() if require_algorithm else None
    required_seen = False

    for algo, digest_b64 in entries:
        algo_lower = algo.lower()
        if algo_lower not in _SUPPORTED_ALGOS:
            # Unknown algos are skipped per RFC 9530 (we only verify what
            # we understand).
            continue
        if required_alg and algo_lower == required_alg:
            required_seen = True
        try:
            expected_bytes = base64.b64decode(digest_b64, validate=True)
        except Exception as e:
            raise ContentDigestError(
                f"digest entry {algo_lower!r} is not valid base64: {e}"
            ) from e
        actual_bytes = _SUPPORTED_ALGOS[algo_lower](bytes(body)).digest()
        if expected_bytes != actual_bytes:
            raise ContentDigestError(
                f"digest mismatch on {algo_lower}: header claims "
                f"{digest_b64} but body hashes to "
                f"{base64.b64encode(actual_bytes).decode('ascii')}"
            )

    if required_alg and not required_seen:
        raise ContentDigestError(
            f"required algorithm {required_alg!r} not present in header"
        )

    return True
