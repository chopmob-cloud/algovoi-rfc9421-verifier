# algovoi-substrate (Python)

AlgoVoi agentic-payments substrate reference implementation.

JCS RFC 8785 canonicalisation, `action_ref` atomic primitive, composite
trust-query algorithm, compliance receipt shape, and audit chain primitives
that compose the substrate underneath x402, AP2, A2A, and MPP receipts.

The substrate runs in production at `https://api.algovoi.co.uk/compliance`.
This package is the AlgoVoi-authored reference implementation; cross-validated
byte-for-byte against four other JCS implementations (JavaScript `canonicalize`,
Go `gowebpki/jcs`, Java `cyberphone`, Rust `serde_jcs`) on 53 conformance
vectors and 3 composite-trust-query vectors.

## Install

```bash
pip install algovoi-substrate
```

## Quickstart

```python
from algovoi_substrate import (
    canonicalize,
    sha256_jcs,
    action_ref,
    composite_trust_query_hash,
    build_compliance_receipt,
    append_to_chain,
    verify_audit_chain,
)

# Canonicalise an object to RFC 8785 JCS bytes.
canonicalize({"b": 1, "a": 2})  # -> '{"a":2,"b":1}'

# The action_ref atomic primitive:
# SHA-256(JCS({agent_id, action_type, scope, timestamp_ms}))
ref = action_ref(
    agent_id="agent-x",
    action_type="payment",
    scope="bilateral",
    timestamp_ms=1716460800000,
)

# Composite trust-query (PR #2440 in x402-foundation/x402).
# Aggregates multi-source attestations into a single canonical hash.
rows = [
    {"source_id": "trust-a", "score": 80, "sig": "sig-bytes"},
    {"source_id": "trust-b", "score": 75, "sig": "sig-bytes"},
]
composite_hash = composite_trust_query_hash(rows)

# Compliance receipt (AlgoVoi production schema).
receipt = build_compliance_receipt(
    payer_ref="sha256:abc123",
    screen_result="ALLOW",
    screen_timestamp_ms=1716460800000,
    screen_provider_did="did:web:api.algovoi.co.uk",
    jurisdiction_flags=["UK", "EU"],
)

# Audit chain: monotonic per-row hash chain with content_hash + prev_hash.
row0 = append_to_chain(payload=dict(receipt), prev_row=None)
row1 = append_to_chain(payload={"event": "next"}, prev_row=row0)
verify_audit_chain([row0, row1])
```

## Substrate discipline

This package enforces the AlgoVoi-discipline rules formalised in PR #2436
(x402-foundation/x402, three-voice coalition co-signed):

- **Rule 1.** `timestamp_ms` is an epoch-millisecond integer. Floats, ISO 8601
  strings, and negative values are rejected at the source-side.
- **Rule 4.** Type validation happens before canonicalisation. A field
  declared integer that receives a float is a hard validation failure, not
  a silent type-cast.
- **canon_version pin.** Receipts carry `canon_version: "jcs-rfc8785-v1"`
  as an in-band format-version pin, so a year-five re-canonicalisation
  knows which rule was active at emission without depending on an
  out-of-band rule registry.
- **Array element order preserved.** `["UK","EU"]` and `["EU","UK"]` are
  distinct canonical preimages per RFC 8785 §3.2.3 -- producer-side
  ordering is load-bearing.

The categorical screen result (`ALLOW` / `REFER` / `DENY`) is enforced as a
closed set. Under UK POCA 2002 s.330 a `REFER` carries a mandatory SAR
obligation that `DENY` does not; collapsing this to a score / tier
projection would lose the property and break year-five auditability.

## Cross-impl validation

The substrate has been byte-for-byte cross-validated across five
implementations on the AlgoVoi-authored vector sets:

- Python `rfc8785@0.1.4` (this package wraps it)
- JavaScript `canonicalize@3.0.0`
- Go `gowebpki/jcs v1.0.1`
- Java `cyberphone/json-canonicalization`
- Rust `serde_jcs@0.2.0`

Vector sets (Apache 2.0, AlgoVoi-authored):

- [AP2 OMH v0](https://gist.github.com/chopmob-cloud/1dca25fd6107db4b7a30bed5dbf2ded8) -- 10 vectors
- [CTEF + APS v1](https://gist.github.com/chopmob-cloud/5f35eaa527d292bf3ddc52f8725a85c9) -- 14 vectors
- [privacy_class v0.1](https://gist.github.com/chopmob-cloud/30bcbc717c86493f737feb92c415ba07) -- 10 vectors
- [per-chain envelope v0](https://gist.github.com/chopmob-cloud/e1bf4c9efde6f0e94b77c238cb33d78d) -- 19 vectors

Substrate matrix: <https://gist.github.com/chopmob-cloud/b327814c4e17ed9fc7b4f29c8bda523c>

Composite trust-query matrix:
<https://gist.github.com/chopmob-cloud/f2e9f0877b7d9fff70c8eca46e4ce636>

## Tests

```bash
pip install -e ".[test]"
pytest
```

## Production reference

The reference exhibit for this substrate is AlgoVoi's `/compliance/attestation`
audit chain, live at `https://api.algovoi.co.uk/compliance/attestation`.
Receipts retained under seven-year Object Lock COMPLIANCE retention (current
horizon 2033-05-04). The migration boundary (receipts before / after
2026-05-21) is observable directly from the chain.

## Spec references

- [PR #2436](https://github.com/x402-foundation/x402/pull/2436) -- canonicalisation discipline
- [PR #2440](https://github.com/x402-foundation/x402/pull/2440) -- composite trust-query
- [PR #2434](https://github.com/x402-foundation/x402/pull/2434) -- compliance-receipt-fixture
- [draft-vauban-x402-stark-receipts](https://datatracker.ietf.org/doc/draft-vauban-x402-stark-receipts/) -- IETF I-D normatively referencing the substrate

## Licence

Apache 2.0. See `LICENSE`.

## Author

AlgoVoi (Christopher Hopley, GitHub `chopmob-cloud`).
