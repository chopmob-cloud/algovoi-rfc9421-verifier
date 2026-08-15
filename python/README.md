# algovoi-rfc9421-verifier (Python)

AlgoVoi-authored reference verifier for
[RFC 9421 (HTTP Message Signatures)](https://www.rfc-editor.org/rfc/rfc9421)
plus
[RFC 9530 (Digest Fields for HTTP)](https://www.rfc-editor.org/rfc/rfc9530).
Python and TypeScript, byte-for-byte parity, Apache 2.0.

## What it does

- Verify an incoming RFC 9421-signed HTTP request against a known public key.
- Re-validate a captured request after it traverses a TLS-re-terminating proxy
  chain (the property pinned in the `rfc9421_proxy_chain_v0` conformance
  fixture).
- Build conformance test harnesses anchored to the RFC 8032 Section 7.1
  deterministic Ed25519 reference keypair.

This package verifies HTTP message signatures (RFC 9421 + RFC 9530): the
wire-level signing-base reconstruction, the Content-Digest check, and the
Ed25519 signature check against a supplied public key. That is a different
surface from the AlgoVoi JCS RFC 8785 receipt-body discipline. HTTP signature
verification (this package) and receipt-content verification (the AlgoVoi
receipt-format packages) are complementary: this verifier confirms wire-level
message integrity; the JCS substrate confirms receipt-body canonical integrity.

## Verification options

`verify_request` applies hardening on top of the signature check. Verifying the
signature alone does not make an authentic request *safe*; these arguments enforce
freshness, coverage, and algorithm policy:

- `required_components` — reject unless every listed component (e.g. `@method`,
  `@authority`, `@path`) is covered by the signature (closes request-line-rewrite gaps).
- `require_content_digest` (default `True`) — require `content-digest` to be a
  covered component and verify it against the body (no body-swap).
- `allowed_algorithms` (default `{"ed25519"}`) — algorithm allow-list; an absent
  `alg` is always rejected.
- `now`, `max_age_seconds`, `max_skew_seconds`, `require_created`,
  `enforce_expires` — freshness window; only *signed* `created` / `expires` are trusted.
- `nonce_seen` — single-use nonce store probe `(nonce, keyid) -> seen`, checked
  after the signature verifies; fails closed on a store error.
- `expected_tag` / `require_tag` — enforce the RFC 9421 `tag` (anti cross-protocol reuse).

Always on: non-canonical, off-curve, and small-order Ed25519 public keys are rejected
before verification, and the `Signature` value must be canonical base64.

```python
from algovoi_rfc9421_verifier import verify_request

result = verify_request(
    method="POST", authority="api.example", path="/pay",
    headers=headers, body=body, public_key=pubkey_hex,
    required_components=["@method", "@authority", "@path"],
    require_created=True, max_age_seconds=300,
    nonce_seen=store.seen,
)
if not result.valid:
    ...  # deny
```

## Install

```
pip install algovoi-rfc9421-verifier
```

## License

Apache 2.0. See [LICENSE](../LICENSE).
