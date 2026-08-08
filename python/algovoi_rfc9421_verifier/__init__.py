"""
algovoi-rfc9421-verifier -- AlgoVoi RFC 9421 HTTP Message Signatures
+ RFC 9530 Content-Digest verification reference implementation.

Use cases:
- Verify an incoming HTTP request's RFC 9421 signature against a known
  public key.
- Re-validate a captured request after it traverses a TLS-re-terminating
  proxy chain (the property pinned in the
  algovoi-jcs-conformance-vectors/rfc9421_proxy_chain_v0 fixture).
- Build conformance test harnesses that anchor to an Ed25519 reference
  keypair from RFC 8032 Section 7.1.

The library is Apache 2.0, has a single runtime dependency (PyNaCl for
Ed25519), and is decoupled from any specific application protocol. It
is paired with the matching TypeScript implementation at
@algovoi/rfc9421-verifier on npm.
"""

from algovoi_rfc9421_verifier.parse import (
    SignatureInputParseError,
    parse_signature_input,
    parse_signature_value,
)
from algovoi_rfc9421_verifier.signing_base import (
    SigningBaseError,
    build_signing_base,
)
from algovoi_rfc9421_verifier.content_digest import (
    ContentDigestError,
    compute_content_digest,
    verify_content_digest,
)
from algovoi_rfc9421_verifier.freshness import (
    FreshnessError,
    check_freshness,
)
from algovoi_rfc9421_verifier.keycheck import (
    WeakKeyError,
    check_ed25519_public_key,
    is_small_order,
)

# NB: keyid resolution (did:key / did:web / HTTPS keyid -> Ed25519 key), which
# does outbound network I/O with an SSRF surface, lives in the separate
# `algovoi-rfc9421-keyid` package. Keeping it out of this package preserves the
# verifier as a pure, offline function.
from algovoi_rfc9421_verifier.verify import (
    VerifyResult,
    VerifyError,
    verify_signature,
    verify_request,
)

__version__ = "0.4.2"

__all__ = [
    # parse
    "SignatureInputParseError",
    "parse_signature_input",
    "parse_signature_value",
    # signing_base
    "SigningBaseError",
    "build_signing_base",
    # content_digest
    "ContentDigestError",
    "compute_content_digest",
    "verify_content_digest",
    # freshness
    "FreshnessError",
    "check_freshness",
    # verify
    "VerifyResult",
    "VerifyError",
    "verify_signature",
    "verify_request",
    # keycheck (trust-boundary public-key gate)
    "WeakKeyError",
    "check_ed25519_public_key",
    "is_small_order",
]
