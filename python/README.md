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

## Install

```
pip install algovoi-rfc9421-verifier
```

## License

Apache 2.0. See [LICENSE](../LICENSE).
