/**
 * Sprint A hardening tests (v0.4.0) -- mirror of the Python
 * test_freshness.py, test_tag.py, and test_alg_hardening.py suites.
 *
 * The Python tests lean on the algovoi_rfc9421_signer package. This repo has
 * no bundled TS signer, so we sign fixtures inline with @noble/ed25519 over the
 * exact RFC 9421 signing base produced by the repo's own buildSigningBase
 * (byte-for-byte the same construction the Python signer performs).
 */
import { describe, expect, it } from "vitest";
import * as ed from "@noble/ed25519";

import {
  FreshnessError,
  checkFreshness,
  buildSigningBase,
  computeContentDigest,
  verifyRequest,
  parseSignatureValue,
  SignatureInputParseError,
} from "../src/index.js";

// RFC 8032 §7.1 Test 2 deterministic keypair (same seed the Python suites use).
const SEED_HEX =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55";
const PUBKEY_HEX =
  "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41";
const SEED = Uint8Array.from(Buffer.from(SEED_HEX, "hex"));

const AUTHORITY = "api.algovoi.co.uk";
const PATH = "/compliance/attestation";
const METHOD = "GET";
const KEYID = "did:web:api.algovoi.co.uk";
const BASE_TIME = 1778955520;
const TAG = "algovoi-a2a-v1";

const DEFAULT_COVERED = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
  "created",
];

interface SignOpts {
  created?: number;
  expires?: number;
  nonce?: string;
  tag?: string;
  coveredComponents?: string[];
  algorithm?: string;
}

/** Mirror of algovoi_rfc9421_signer._params_block. */
function paramsBlock(
  covered: string[],
  {
    created,
    keyid,
    algorithm,
    expires,
    nonce,
    tag,
  }: {
    created: number;
    keyid: string;
    algorithm: string;
    expires?: number;
    nonce?: string;
    tag?: string;
  },
): string {
  const inner = covered.map((c) => `"${c}"`).join(" ");
  const parts = [`(${inner})`, `;created=${created}`];
  if (expires !== undefined) parts.push(`;expires=${expires}`);
  parts.push(`;keyid="${keyid}"`);
  parts.push(`;alg="${algorithm}"`);
  if (nonce !== undefined) parts.push(`;nonce="${nonce}"`);
  if (tag !== undefined) parts.push(`;tag="${tag}"`);
  return parts.join("");
}

/** Mirror of algovoi_rfc9421_signer.sign_request over an empty body. */
async function sign(opts: SignOpts = {}): Promise<Record<string, string>> {
  const covered = opts.coveredComponents ?? [...DEFAULT_COVERED];
  const created = opts.created ?? BASE_TIME;
  const algorithm = opts.algorithm ?? "ed25519";
  const body = new Uint8Array();
  const cd = computeContentDigest(body);

  const params = paramsBlock(covered, {
    created,
    keyid: KEYID,
    algorithm,
    expires: opts.expires,
    nonce: opts.nonce,
    tag: opts.tag,
  });

  const parameters: Record<string, string | number> = {
    created,
    keyid: KEYID,
    alg: algorithm,
  };
  if (opts.expires !== undefined) parameters.expires = opts.expires;
  if (opts.nonce !== undefined) parameters.nonce = opts.nonce;
  if (opts.tag !== undefined) parameters.tag = opts.tag;

  const signingBase = buildSigningBase({
    coveredComponents: covered,
    method: METHOD,
    authority: AUTHORITY,
    path: PATH,
    headers: { "content-digest": cd },
    parameters,
    mode: "rfc9421",
    signatureParamsRaw: params,
  });

  const sigBytes = await ed.signAsync(
    new TextEncoder().encode(signingBase),
    SEED,
  );
  const sigB64 = Buffer.from(sigBytes).toString("base64");

  return {
    host: AUTHORITY,
    "content-digest": cd,
    "signature-input": `sig=${params}`,
    signature: `sig=:${sigB64}:`,
  };
}

function verify(
  headers: Record<string, string>,
  extra: Partial<Parameters<typeof verifyRequest>[0]> = {},
) {
  return verifyRequest({
    method: METHOD,
    authority: AUTHORITY,
    path: PATH,
    headers,
    body: new Uint8Array(),
    publicKey: PUBKEY_HEX,
    ...extra,
  });
}

// --- Sprint A item 1: freshness + replay ---

describe("freshness", () => {
  it("fresh created passes", async () => {
    const headers = await sign({ created: BASE_TIME });
    const result = await verify(headers, {
      now: BASE_TIME + 5,
      maxAgeSeconds: 300,
    });
    expect(result.valid).toBe(true);
  });

  it("expired signature fails", async () => {
    const covered = [...DEFAULT_COVERED, "expires"];
    const headers = await sign({
      created: BASE_TIME,
      expires: BASE_TIME + 100,
      coveredComponents: covered,
    });
    const result = await verify(headers, { now: BASE_TIME + 10_000 });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.toLowerCase().includes("expired"))).toBe(
      true,
    );
  });

  it("future created beyond skew fails", async () => {
    const headers = await sign({ created: BASE_TIME + 10_000 });
    const result = await verify(headers, {
      now: BASE_TIME,
      requireCreated: true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.toLowerCase().includes("future"))).toBe(
      true,
    );
  });

  it("created within skew passes", async () => {
    const headers = await sign({ created: BASE_TIME + 30 });
    const result = await verify(headers, {
      now: BASE_TIME,
      requireCreated: true,
      maxSkewSeconds: 60,
    });
    expect(result.valid).toBe(true);
  });

  it("older than max age fails", async () => {
    const headers = await sign({ created: BASE_TIME });
    const result = await verify(headers, {
      now: BASE_TIME + 10_000,
      maxAgeSeconds: 300,
    });
    expect(result.valid).toBe(false);
    expect(
      result.errors.some(
        (e) =>
          e.toLowerCase().includes("older") || e.toLowerCase().includes("age"),
      ),
    ).toBe(true);
  });

  it("static fixture old created passes when max age off", async () => {
    const headers = await sign({ created: BASE_TIME });
    const result = await verify(headers, { now: BASE_TIME + 10_000_000 });
    expect(result.valid).toBe(true);
  });

  it("expires present and past fails even when max age off", async () => {
    const covered = [...DEFAULT_COVERED, "expires"];
    const headers = await sign({
      created: BASE_TIME,
      expires: BASE_TIME + 100,
      coveredComponents: covered,
    });
    const result = await verify(headers, { now: BASE_TIME + 10_000 });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.toLowerCase().includes("expired"))).toBe(
      true,
    );
  });

  it("replayed nonce fails", async () => {
    const headers = await sign({ created: BASE_TIME, nonce: "nonce-abc" });
    const result = await verify(headers, {
      now: BASE_TIME + 5,
      nonceSeen: () => true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.toLowerCase().includes("replay"))).toBe(
      true,
    );
  });

  it("fresh nonce passes", async () => {
    const headers = await sign({ created: BASE_TIME, nonce: "nonce-xyz" });
    const result = await verify(headers, {
      now: BASE_TIME + 5,
      nonceSeen: () => false,
    });
    expect(result.valid).toBe(true);
  });

  it("nonce store error fails closed", async () => {
    const headers = await sign({ created: BASE_TIME, nonce: "nonce-boom" });
    const result = await verify(headers, {
      now: BASE_TIME + 5,
      nonceSeen: () => {
        throw new Error("store down");
      },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.toLowerCase().includes("store"))).toBe(
      true,
    );
  });

  // unit-level checkFreshness
  it("checkFreshness rejects uncovered created when required (params unsigned)", () => {
    expect(() =>
      checkFreshness({ created: BASE_TIME }, ["@method", "@path"], {
        now: BASE_TIME,
        requireCreated: true,
        paramsSigned: false,
      }),
    ).toThrow(FreshnessError);
  });

  it("checkFreshness rejects uncovered expires (params unsigned)", () => {
    expect(() =>
      checkFreshness({ expires: BASE_TIME + 100 }, ["@method", "@path"], {
        now: BASE_TIME,
        paramsSigned: false,
      }),
    ).toThrow(FreshnessError);
  });

  it("checkFreshness trusts a created PARAM (not a covered component) in rfc9421 mode", () => {
    // In rfc9421 mode @signature-params carries created/expires and is signed,
    // so freshness is enforceable on the param even when it is not also a
    // covered component. paramsSigned defaults to true.
    expect(() =>
      checkFreshness({ created: BASE_TIME }, ["@method", "@path"], {
        now: BASE_TIME + 5,
        maxAgeSeconds: 300,
        requireCreated: true,
      }),
    ).not.toThrow();
  });

  it("verifyRequest enforces freshness on a created PARAM not listed as covered", async () => {
    // Sign covering only @method/@authority/@path/content-digest (NOT created),
    // but created still rides in @signature-params. rfc9421 mode must trust it.
    const covered = ["@method", "@authority", "@path", "content-digest"];
    const headers = await sign({
      created: BASE_TIME,
      coveredComponents: covered,
    });
    const result = await verify(headers, {
      now: BASE_TIME + 10,
      maxAgeSeconds: 300,
      requireCreated: true,
    });
    expect(result.valid).toBe(true);
  });
});

// --- Sprint A item 2: tag ---

describe("tag", () => {
  it("matching tag passes", async () => {
    const headers = await sign({ tag: TAG });
    const result = await verify(headers, { expectedTag: TAG });
    expect(result.valid).toBe(true);
    expect(result.parameters["tag"]).toBe(TAG);
  });

  it("wrong tag fails", async () => {
    const headers = await sign({ tag: TAG });
    const result = await verify(headers, {
      expectedTag: "some-other-context",
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.toLowerCase().includes("tag"))).toBe(
      true,
    );
  });

  it("missing tag fails when required", async () => {
    const headers = await sign();
    const result = await verify(headers, { requireTag: true });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.toLowerCase().includes("tag"))).toBe(
      true,
    );
  });

  it("missing tag ignored when not required", async () => {
    const headers = await sign();
    const result = await verify(headers);
    expect(result.valid).toBe(true);
  });

  it("signer emits a bound tag (tampering breaks the signature)", async () => {
    const headers = await sign({ tag: TAG });
    const tampered = { ...headers };
    tampered["signature-input"] = headers["signature-input"].replace(
      `tag="${TAG}"`,
      'tag="attacker-swapped"',
    );
    const result = await verify(tampered, { expectedTag: "attacker-swapped" });
    expect(result.valid).toBe(false);
    expect(result.signature_valid).toBe(false);
  });
});

// --- Sprint A item 3: algorithm-downgrade hardening ---

describe("alg hardening", () => {
  it("ed25519 passes", async () => {
    const result = await verify(await sign());
    expect(result.valid).toBe(true);
  });

  it("absent alg fails", async () => {
    const headers = await sign();
    headers["signature-input"] = headers["signature-input"].replace(
      ';alg="ed25519"',
      "",
    );
    const result = await verify(headers);
    expect(result.valid).toBe(false);
    expect(
      result.errors.some(
        (e) =>
          e.toLowerCase().includes("alg") &&
          e.toLowerCase().includes("missing"),
      ),
    ).toBe(true);
  });

  it("disallowed alg fails", async () => {
    const result = await verify(await sign(), {
      allowedAlgorithms: ["ecdsa-p256-sha256"],
    });
    expect(result.valid).toBe(false);
    expect(
      result.errors.some((e) => e.includes("not in the allowed set")),
    ).toBe(true);
  });

  it("allow-list with ed25519 passes", async () => {
    const result = await verify(await sign(), {
      allowedAlgorithms: ["ed25519", "ecdsa-p256-sha256"],
    });
    expect(result.valid).toBe(true);
  });
});

describe("signature value base64 canonicality", () => {
  // Node's Buffer.from(_, "base64") is lenient; the parser must fail closed on
  // non-canonical / malformed encodings so ~16 encodings of one signature do
  // not all verify (signature-string malleability -> broken replay/dedup keys).
  const canonical = Buffer.from(Uint8Array.from({ length: 64 }, (_, i) => i)).toString("base64");

  it("accepts canonical base64", () => {
    const { signature } = parseSignatureValue(`sig=:${canonical}:`);
    expect(signature.length).toBe(64);
  });

  it("rejects non-canonical base64 (non-zero pad bits)", () => {
    // Find an encoding that decodes to the SAME 64 bytes but differs in string:
    // that is a non-canonical alias of the signature (the malleability we reject).
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const padStart = canonical.indexOf("=");
    const stem = canonical.slice(0, padStart - 1);
    const pad = canonical.slice(padStart);
    const want = Buffer.from(canonical, "base64");
    let noncanon = "";
    for (const ch of alphabet) {
      const cand = stem + ch + pad;
      if (cand !== canonical && Buffer.from(cand, "base64").equals(want)) {
        noncanon = cand;
        break;
      }
    }
    expect(noncanon).not.toBe("");
    expect(() => parseSignatureValue(`sig=:${noncanon}:`)).toThrow(SignatureInputParseError);
  });

  it("rejects characters outside the base64 alphabet", () => {
    expect(() => parseSignatureValue("sig=:not+valid+base64!!:")).toThrow(SignatureInputParseError);
  });
});
