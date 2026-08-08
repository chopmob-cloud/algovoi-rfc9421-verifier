/**
 * @algovoi/rfc9421-verifier tests -- mirror of Python tests.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";

import {
  SignatureInputParseError,
  buildSigningBase,
  computeContentDigest,
  parseSignatureInput,
  parseSignatureValue,
  verifyContentDigest,
  verifyRequest,
  verifySignature,
} from "../src/index.js";

// RFC 8032 Section 7.1 Test 1 reference keypair
const RFC8032_PUBKEY_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

const FIXTURE_HEADERS: Record<string, string> = {
  host: "api.algovoi.co.uk",
  "content-digest":
    "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
  "signature-input":
    'sig=("@method" "@authority" "@path" "content-digest" "created");created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"',
  signature:
    "sig=:Xj1peMjEYi75R/QQFYpU9q/gHwQKYwgt1etjAX1qc0zugTMJoJ86Uhy/jTZ175b3zFhp0j8cLjmDJvGmySDBAQ==:",
};

// algovoi-v0 fixture: @method lowercased, "created" covered, no
// @signature-params line. Verified with mode "algovoi-v0".
const FIXTURE_SIGNING_BASE =
  '"@method": get\n' +
  '"@authority": api.algovoi.co.uk\n' +
  '"@path": /compliance/attestation\n' +
  '"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\n' +
  '"created": 1778955520';

// RFC 9421 fixture (v0.3.0 default): @method case-preserved, "created"
// a parameter (not a covered component), and the @signature-params line
// appended per RFC 9421 §2.5. Same RFC 8032 §7.1 Test 1 keypair as above.
// Matches the rfc9421_proxy_chain_v1 conformance vector.
const FIXTURE_HEADERS_RFC9421: Record<string, string> = {
  host: "api.algovoi.co.uk",
  "content-digest":
    "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
  "signature-input":
    'sig=("@method" "@authority" "@path" "content-digest");created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"',
  signature:
    "sig=:qWRuNCsCUyKO/9MNtGApDxeznFm+07DyK4zN6eF/mnRcrQ3IaRpQOjQxY6xetCL+588L02Ajd3RjUR9jGi2jBw==:",
};

const FIXTURE_SIGNING_BASE_RFC9421 =
  '"@method": GET\n' +
  '"@authority": api.algovoi.co.uk\n' +
  '"@path": /compliance/attestation\n' +
  '"content-digest": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\n' +
  '"@signature-params": ("@method" "@authority" "@path" "content-digest");created=1778955520;keyid="did:web:api.algovoi.co.uk";alg="ed25519"';

describe("parseSignatureInput", () => {
  it("parses the full labelled form", () => {
    const si = parseSignatureInput(FIXTURE_HEADERS["signature-input"]);
    expect(si.label).toBe("sig");
    expect(si.covered_components).toEqual([
      "@method",
      "@authority",
      "@path",
      "content-digest",
      "created",
    ]);
    expect(si.parameters["created"]).toBe(1778955520);
    expect(si.parameters["alg"]).toBe("ed25519");
  });

  it("accepts the unlabelled form", () => {
    const si = parseSignatureInput('("@method" "@path");created=1');
    expect(si.label).toBe("");
    expect(si.covered_components).toEqual(["@method", "@path"]);
    expect(si.parameters["created"]).toBe(1);
  });

  it("rejects empty input", () => {
    expect(() => parseSignatureInput("")).toThrow(SignatureInputParseError);
  });

  it("rejects garbage input", () => {
    expect(() => parseSignatureInput("totally-garbage-input")).toThrow(
      SignatureInputParseError,
    );
  });
});

describe("parseSignatureValue", () => {
  it("parses signature header", () => {
    const { label, signature } = parseSignatureValue(FIXTURE_HEADERS.signature);
    expect(label).toBe("sig");
    expect(signature.length).toBe(64);
  });

  it("rejects missing colons", () => {
    expect(() => parseSignatureValue("sig=Xj1pe")).toThrow(
      SignatureInputParseError,
    );
  });
});

describe("buildSigningBase", () => {
  it("matches the fixture signing base byte-for-byte", () => {
    const si = parseSignatureInput(FIXTURE_HEADERS["signature-input"]);
    const base = buildSigningBase({
      coveredComponents: si.covered_components,
      method: "GET",
      authority: "api.algovoi.co.uk",
      path: "/compliance/attestation",
      headers: FIXTURE_HEADERS,
      parameters: si.parameters,
    });
    expect(base).toBe(FIXTURE_SIGNING_BASE);
  });
});

describe("computeContentDigest", () => {
  it("empty body produces the documented SHA-256 base64", () => {
    expect(computeContentDigest(new Uint8Array())).toBe(
      "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    );
  });
});

describe("verifyContentDigest", () => {
  it("accepts empty body matching the empty-body digest", () => {
    expect(
      verifyContentDigest(new Uint8Array(), FIXTURE_HEADERS["content-digest"]),
    ).toBe(true);
  });

  it("throws on body mismatch", () => {
    expect(() =>
      verifyContentDigest(
        new TextEncoder().encode("non-empty"),
        FIXTURE_HEADERS["content-digest"],
      ),
    ).toThrow();
  });
});

describe("verifySignature", () => {
  it("verifies the fixture signature", async () => {
    const { signature } = parseSignatureValue(FIXTURE_HEADERS.signature);
    const ok = await verifySignature(
      FIXTURE_SIGNING_BASE,
      signature,
      RFC8032_PUBKEY_HEX,
    );
    expect(ok).toBe(true);
  });

  it("rejects a tampered signing base", async () => {
    const { signature } = parseSignatureValue(FIXTURE_HEADERS.signature);
    const tampered = FIXTURE_SIGNING_BASE.replace("get", "post");
    expect(await verifySignature(tampered, signature, RFC8032_PUBKEY_HEX)).toBe(
      false,
    );
  });

  it("rejects a wrong public key", async () => {
    const { signature } = parseSignatureValue(FIXTURE_HEADERS.signature);
    // A genuinely valid, large-order public key that is NOT this fixture's
    // signer (the pubkey for seed …cae3d55). The signature must not verify.
    const wrongKey =
      "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41";
    expect(
      await verifySignature(FIXTURE_SIGNING_BASE, signature, wrongKey),
    ).toBe(false);
  });

  it("rejects a small-order public key (trust-boundary gate)", async () => {
    const { signature } = parseSignatureValue(FIXTURE_HEADERS.signature);
    // The all-zeros key is a small-order point; the gate throws before verify.
    await expect(
      verifySignature(FIXTURE_SIGNING_BASE, signature, "00".repeat(32)),
    ).rejects.toThrow();
  });
});

describe("verifyRequest (end-to-end)", () => {
  it("passes the rfc9421 fixture end-to-end (default mode)", async () => {
    const result = await verifyRequest({
      method: "GET",
      authority: "api.algovoi.co.uk",
      path: "/compliance/attestation",
      headers: FIXTURE_HEADERS_RFC9421,
      body: new Uint8Array(),
      publicKey: RFC8032_PUBKEY_HEX,
    });
    expect(result.valid).toBe(true);
    expect(result.signature_valid).toBe(true);
    expect(result.content_digest_valid).toBe(true);
    expect(result.signing_base).toBe(FIXTURE_SIGNING_BASE_RFC9421);
    expect(result.label).toBe("sig");
    expect(result.errors).toEqual([]);
  });

  it("passes the algovoi-v0 fixture with explicit mode", async () => {
    const result = await verifyRequest({
      method: "GET",
      authority: "api.algovoi.co.uk",
      path: "/compliance/attestation",
      headers: FIXTURE_HEADERS,
      body: new Uint8Array(),
      publicKey: RFC8032_PUBKEY_HEX,
      mode: "algovoi-v0",
    });
    expect(result.valid).toBe(true);
    expect(result.signing_base).toBe(FIXTURE_SIGNING_BASE);
  });

  it("fails when signature-input is missing", async () => {
    const headers = { ...FIXTURE_HEADERS_RFC9421 };
    delete headers["signature-input"];
    const result = await verifyRequest({
      method: "GET",
      authority: "api.algovoi.co.uk",
      path: "/compliance/attestation",
      headers,
      body: new Uint8Array(),
      publicKey: RFC8032_PUBKEY_HEX,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Signature-Input"))).toBe(true);
  });

  it("fails when path is tampered", async () => {
    const result = await verifyRequest({
      method: "GET",
      authority: "api.algovoi.co.uk",
      path: "/different/path",
      headers: FIXTURE_HEADERS_RFC9421,
      body: new Uint8Array(),
      publicKey: RFC8032_PUBKEY_HEX,
    });
    expect(result.valid).toBe(false);
    expect(result.signature_valid).toBe(false);
  });

  it("fails when body does not match content-digest", async () => {
    const result = await verifyRequest({
      method: "GET",
      authority: "api.algovoi.co.uk",
      path: "/compliance/attestation",
      headers: FIXTURE_HEADERS_RFC9421,
      body: new TextEncoder().encode("non-empty"),
      publicKey: RFC8032_PUBKEY_HEX,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Content-Digest"))).toBe(true);
  });

  it("validates the rfc9421_proxy_chain_v1 corpus fixture (default mode)", async () => {
    const fixturePath =
      "C:/algo/algovoi-jcs-conformance-vectors/vectors/rfc9421_proxy_chain_v1/request.fixture.json";
    if (!existsSync(fixturePath)) {
      // Skip when the corpus is not co-located
      return;
    }
    const fixture = JSON.parse(readFileSync(fixturePath, "utf-8"));
    const req = fixture.request;
    const result = await verifyRequest({
      method: req.method,
      authority: req.authority,
      path: req.path,
      headers: req.headers,
      body: new Uint8Array(),
      publicKey: fixture.keypair.public_key_hex,
    });
    expect(result.valid).toBe(true);
    expect(result.signing_base).toBe(fixture.signing.signing_base);
  });

  it("validates the rfc9421_proxy_chain_v0 corpus fixture (explicit algovoi-v0)", async () => {
    const fixturePath =
      "C:/algo/algovoi-jcs-conformance-vectors/vectors/rfc9421_proxy_chain_v0/request.fixture.json";
    if (!existsSync(fixturePath)) {
      // Skip when the corpus is not co-located
      return;
    }
    const fixture = JSON.parse(readFileSync(fixturePath, "utf-8"));
    const req = fixture.request;
    const result = await verifyRequest({
      method: req.method,
      authority: req.authority,
      path: req.path,
      headers: req.headers,
      body: new Uint8Array(),
      publicKey: fixture.keypair.public_key_hex,
      mode: "algovoi-v0",
    });
    expect(result.valid).toBe(true);
    expect(result.signing_base).toBe(fixture.signing.signing_base);
  });
});
