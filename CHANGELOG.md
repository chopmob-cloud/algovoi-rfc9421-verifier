# Changelog

All notable changes to `algovoi-rfc9421-verifier` (Python) and
`@algovoi/rfc9421-verifier` (npm) are documented here. Both packages
ship in lock-step at the same version.

## 0.2.1 — 2026-05-27

### Changed

- Default value of `require_algorithm` / `requireAlgorithm` parameter
  on `verify_request` / `verifyRequest` changed from `"sha-256"` to
  `None` / `null` (no algorithm requirement). When unspecified, the
  verifier now accepts any RFC 9530-registered algorithm it supports
  (currently SHA-256 and SHA-512) present in the Content-Digest
  header and verifies it against the body.

  This makes the common case work transparently: a request whose
  Content-Digest carries SHA-512 (as Envoys-style implementations do
  for bodies ≥4096 bytes per RFC 9530 §3) now verifies without the
  caller having to pre-inspect the header or opt out of strict mode.

  To enforce a specific algorithm (the previous default behaviour),
  pass `require_algorithm="sha-256"` / `requireAlgorithm: "sha-256"`
  explicitly.

### Compatibility

This change is strictly more permissive than 0.2.0:

- Callers who passed nothing and had a `sha-256=...` Content-Digest
  header continue to verify identically.
- Callers who passed `"sha-256"` continue to enforce SHA-256 only.
- Callers who passed `None` / `null` continue to skip the algorithm
  requirement.
- The only behaviour change is for callers who passed nothing and
  whose Content-Digest header carried `sha-512=...` only — those
  failed in 0.2.0 with "required algorithm 'sha-256' not present in
  header" and now succeed.

No public API surface changes, no breaking changes to existing tests
(20 Python + 18 TypeScript pass unchanged), and the full 7-of-7
cross-validation against external Envoys and Hippo fixtures now
passes with no flag at all (vec-5 SHA-512 included).

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
