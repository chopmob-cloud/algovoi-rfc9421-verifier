/**
 * RC-1: requiredComponents policy tests (TypeScript parity with the Python
 * test_required_components.py). A signature over a narrow covered set is
 * cryptographically valid but may omit request-line components; when the caller
 * pins a required set, a signature omitting any of them is rejected before
 * verification. Signs fixtures inline with @noble/ed25519 over the repo's own
 * buildSigningBase, byte-for-byte the construction the Python signer performs.
 */
import { describe, expect, it } from "vitest";
import * as ed from "@noble/ed25519";

import {
  buildSigningBase,
  computeContentDigest,
  verifyRequest,
} from "../src/index.js";

const SEED_HEX =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55";
const PUBKEY_HEX =
  "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41";
const SEED = Uint8Array.from(Buffer.from(SEED_HEX, "hex"));
const AUTHORITY = "api.algovoi.co.uk";
const PATH = "/compliance/attestation";
const METHOD = "GET";
const KEYID = "did:web:api.algovoi.co.uk";
const CREATED = 1778955520;

async function sign(covered: string[]): Promise<Record<string, string>> {
  const body = new Uint8Array();
  const cd = computeContentDigest(body);
  const inner = covered.map((c) => `"${c}"`).join(" ");
  const params = `(${inner});created=${CREATED};keyid="${KEYID}";alg="ed25519"`;
  const parameters: Record<string, string | number> = {
    created: CREATED,
    keyid: KEYID,
    alg: "ed25519",
  };
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
  return {
    host: AUTHORITY,
    "content-digest": cd,
    "signature-input": `sig=${params}`,
    signature: `sig=:${Buffer.from(sigBytes).toString("base64")}:`,
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
    now: CREATED + 5,
    ...extra,
  });
}

const FULL = ["@method", "@authority", "@path", "content-digest", "created"];
const NARROW = ["@method", "content-digest", "created"];

describe("RC-1 requiredComponents", () => {
  it("passes when all required components are covered", async () => {
    const headers = await sign(FULL);
    const r = await verify(headers, {
      requiredComponents: ["@method", "@authority", "@path"],
    });
    expect(r.valid).toBe(true);
  });

  it("rejects when a required component is missing", async () => {
    const headers = await sign(NARROW);
    const r = await verify(headers, {
      requiredComponents: ["@method", "@authority", "@path"],
    });
    expect(r.valid).toBe(false);
    expect(
      r.errors.some((e) => e.includes("required covered components missing")),
    ).toBe(true);
  });

  it("does not reject for coverage when no policy is given", async () => {
    const headers = await sign(NARROW);
    const r = await verify(headers);
    expect(
      r.errors.some((e) => e.includes("required covered components missing")),
    ).toBe(false);
    expect(r.valid).toBe(true); // narrow signature is still cryptographically valid
  });
});
