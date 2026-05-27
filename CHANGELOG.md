# Changelog

All notable changes to `algovoi-rfc9421-verifier` (Python) and
`@algovoi/rfc9421-verifier` (npm) are documented here. Both packages
ship in lock-step at the same version.

## 0.2.0 — 2026-05-27

### Added

- `mode` parameter on `verify_request` / `verifyRequest` (and on
  `build_signing_base` / `buildSigningBase`) with two values:
  - `"algovoi-v0"` (default): preserves the v0.1.x behaviour for
    backward compatibility with the AlgoVoi internal fixture and the
    `rfc9421_proxy_chain_v0` conformance set.
  - `"rfc9421"`: full RFC 9421 §2.5 compliance. `@method` is preserved
    as-supplied (HTTP convention is uppercase), and a final
    `"@signature-params"` line is appended to the signing base
    carrying the Inner List + parameters block from the
    `Signature-Input` header verbatim.

- `ParsedSignatureInput.params_block` field exposing the post-label
  portion of the `Signature-Input` header value, which is the value
  the `@signature-params` line must carry under RFC 9421 §2.5.

- TypeScript-side support for `requireAlgorithm: null` (no
  Content-Digest algorithm requirement), to allow verification of
  SHA-512 Content-Digest bodies in `rfc9421` mode.

### Cross-validation

`rfc9421` mode validated byte-for-byte against external RFC 9421
fixture sets:

- Envoys `envoys-rfc9421` (jschoemaker/Envoys-public): 5 of 5
  verifiable positive vectors PASS (vec-1 through vec-5; vec-6 is
  manifest-declared `inputs-only`).
- Hippo `hippo-rfc9421` (opena2a-org/a2a-idf-conformance#2): 2 of 2
  composition vectors PASS (`signature-alone-no-tag`,
  `signature-alone-tag`).

Python: 20 internal unit tests pass unchanged in default
(`algovoi-v0`) mode. TypeScript: 18 internal vitest tests pass
unchanged in default mode.

### Backward compatibility

Default mode is `"algovoi-v0"`, which preserves the v0.1.x signing
base shape. Existing consumers do not need to change anything. RFC
9421 compliance is opt-in via `mode="rfc9421"`.

## 0.1.1 — 2026-05-26

Initial public release. RFC 9421 + RFC 9530 verification with
Ed25519 signature support; Python + TypeScript packages with
byte-for-byte parity on the internal fixture set.

## 0.1.0

Pre-release, not published.
