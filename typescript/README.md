# algovoi-rfc9421-verifier

[![PyPI](https://img.shields.io/pypi/v/algovoi-rfc9421-verifier?label=PyPI)](https://pypi.org/project/algovoi-rfc9421-verifier/)
[![npm](https://img.shields.io/npm/v/@algovoi/rfc9421-verifier?label=npm)](https://www.npmjs.com/package/@algovoi/rfc9421-verifier)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](./LICENSE)
[![IETF I-D](https://img.shields.io/badge/companion%20IETF%20I--D-draft--hopley--x402--compliance--receipt--00-blue)](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)

AlgoVoi-authored reference verifier for
[RFC 9421 (HTTP Message Signatures)](https://www.rfc-editor.org/rfc/rfc9421)
plus
[RFC 9530 (Digest Fields for HTTP)](https://www.rfc-editor.org/rfc/rfc9530).
Python and TypeScript, byte-for-byte parity, Apache 2.0.

Use cases:

- Verify an incoming RFC 9421-signed HTTP request against a known
  public key.
- Re-validate a captured request after it traverses a TLS-re-terminating
  proxy chain (the property pinned in the
  [`rfc9421_proxy_chain_v0`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors/tree/main/vectors/rfc9421_proxy_chain_v0)
  conformance fixture).
- Build conformance test harnesses anchored to the RFC 8032 Section
  7.1 deterministic Ed25519 reference keypair.

## Packages

| Language | Package | Install |
|---|---|---|
| Python | [`algovoi-rfc9421-verifier`](https://pypi.org/project/algovoi-rfc9421-verifier/) | `pip install algovoi-rfc9421-verifier` |
| TypeScript | [`@algovoi/rfc9421-verifier`](https://www.npmjs.com/package/@algovoi/rfc9421-verifier) | `npm install @algovoi/rfc9421-verifier` |

Both packages are byte-deterministic on identical inputs and tested
against the same RFC 8032 Section 7.1 Test 1 reference fixture.

## Quick start

### Python

```python
from algovoi_rfc9421_verifier import verify_request

result = verify_request(
    method="GET",
    authority="api.algovoi.co.uk",
    path="/compliance/attestation",
    headers={
        "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
        "signature-input": (
            'sig=("@method" "@authority" "@path" "content-digest" "created");'
            'created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"'
        ),
        "signature": (
            "sig=:Xj1peMjEYi75R/QQFYpU9q/gHwQKYwgt1etjAX1qc0zugTMJoJ86Uhy/jTZ175b3"
            "zFhp0j8cLjmDJvGmySDBAQ==:"
        ),
    },
    body=b"",
    public_key="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
)
assert result.valid
```

### TypeScript

```typescript
import { verifyRequest } from "@algovoi/rfc9421-verifier";

const result = await verifyRequest({
  method: "GET",
  authority: "api.algovoi.co.uk",
  path: "/compliance/attestation",
  headers: {
    "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    "signature-input":
      'sig=("@method" "@authority" "@path" "content-digest" "created");created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"',
    signature:
      "sig=:Xj1peMjEYi75R/QQFYpU9q/gHwQKYwgt1etjAX1qc0zugTMJoJ86Uhy/jTZ175b3zFhp0j8cLjmDJvGmySDBAQ==:",
  },
  body: new Uint8Array(),
  publicKey:
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
});
if (result.valid) console.log("verified");
```

## API surface (v0.1.0)

| Function | Purpose |
|---|---|
| `verify_request` / `verifyRequest` | High-level: parse all headers, build signing base, verify Content-Digest, verify Ed25519 signature, return a `VerifyResult` with per-step success flags. |
| `verify_signature` / `verifySignature` | Lower-level: caller supplies the signing base; library verifies Ed25519 only. |
| `verify_content_digest` / `verifyContentDigest` | Validate RFC 9530 `Content-Digest` header against a body. SHA-256 and SHA-512 supported. |
| `build_signing_base` / `buildSigningBase` | Construct the RFC 9421 §2.5 signing base from covered components + values. |
| `parse_signature_input` / `parseSignatureInput` | Parse a `Signature-Input` header. Accepts the strict labelled form and the unlabelled real-world form. |
| `parse_signature_value` / `parseSignatureValue` | Parse a `Signature` header. |
| `compute_content_digest` / `computeContentDigest` | Compute a `Content-Digest` header value for a body. |

## Scope (v0.1.0)

- **Algorithms**: Ed25519 only. ECDSA-P256 and RSA-PSS are roadmap.
- **Derived components**: `@method`, `@authority`, `@path`,
  `@target-uri`, `@scheme`, `@status`, plus `created` and `expires`
  parameters. `@request-target`, `@query`, `@query-param` are roadmap.
- **Header forms**: strict labelled `<label>=(...)` and unlabelled
  `(...);created=...` real-world forms both accepted.
- **Content-Digest**: SHA-256 (mandatory per RFC 9530) and SHA-512.
  Other algorithms in the IANA registry are roadmap.

The v0.1.0 surface is sufficient to verify any AlgoVoi production
compliance receipt and the `rfc9421_proxy_chain_v0` conformance
fixture. Multi-algorithm + multi-label support arrives in v0.2.0.

## Conformance fixture

The reference fixture for the verifier is at
[`chopmob-cloud/algovoi-jcs-conformance-vectors/vectors/rfc9421_proxy_chain_v0/`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors/tree/main/vectors/rfc9421_proxy_chain_v0).
It uses the RFC 8032 Section 7.1 Test 1 deterministic Ed25519 keypair
and includes a `tcpdump` wire-capture record (`E2E_PROOF.md`)
demonstrating that the RFC 9421 headers survive a 3-hop
TLS-re-terminating proxy chain (Cloudflare edge → nginx → FastAPI)
byte-identical.

## Companion IETF Internet-Draft

This library is part of the AlgoVoi substrate that anchors
[`draft-hopley-x402-compliance-receipt-00`](https://datatracker.ietf.org/doc/draft-hopley-x402-compliance-receipt/)
(Independent Submission, Informational; posted 2026-05-23). The
receipt-format audit-chain property in the I-D assumes signed
receipts can be transported and re-verified independently of the
originating gateway — exactly the property this verifier checks.

## Related AlgoVoi substrate packages

| Package | Purpose |
|---|---|
| [`algovoi-substrate`](https://pypi.org/project/algovoi-substrate/) / [`@algovoi/substrate`](https://www.npmjs.com/package/@algovoi/substrate) | JCS RFC 8785 canonicalisation, `action_ref`, transactional lifecycle, compliance receipt builder |
| [`algovoi-audit-verifier`](https://pypi.org/project/algovoi-audit-verifier/) / [`@algovoi/audit-verifier`](https://www.npmjs.com/package/@algovoi/audit-verifier) | Selective-disclosure audit bundle verifier; consumes substrate output |
| **`algovoi-rfc9421-verifier`** / `@algovoi/rfc9421-verifier` | **This package.** RFC 9421/9530 HTTP signature verifier |

## Relationship to the canonicalisation discipline

This package verifies HTTP message signatures per RFC 9421 + RFC 9530 -- a different canonicalisation surface from the AlgoVoi JCS RFC 8785 receipt-body discipline at [docs.algovoi.co.uk/canonicalisation-substrate](https://docs.algovoi.co.uk/canonicalisation-substrate). HTTP signature verification (this package) and receipt-content verification (`@algovoi/audit-verifier` + the receipt-format packages) are complementary surfaces: this verifier confirms wire-level message integrity; the AlgoVoi JCS substrate confirms receipt-body canonical integrity. Both are AlgoVoi-authored under sole authorship.

Parties anchoring to the AlgoVoi canonicalisation discipline are recorded in the [Substrate Adopters Registry](https://docs.algovoi.co.uk/adopters); the registry's `canon_version` pin criterion applies to receipt-body artefacts, not to HTTP signatures as such.

## Licence

Apache 2.0. See [`LICENSE`](./LICENSE).

## Author

AlgoVoi (Christopher Hopley, GitHub [`chopmob-cloud`](https://github.com/chopmob-cloud)).
