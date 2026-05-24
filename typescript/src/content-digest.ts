/**
 * RFC 9530 Content-Digest field implementation.
 *
 * Mirror of the Python algovoi_rfc9421_verifier.content_digest module.
 */

import { createHash } from "node:crypto";

export class ContentDigestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContentDigestError";
  }
}

const DIGEST_ENTRY_RE = /([a-z0-9-]+)=:([A-Za-z0-9+/=]+):/g;

const SUPPORTED_ALGOS: Record<string, string> = {
  "sha-256": "sha256",
  "sha-512": "sha512",
};

function bodyBytes(body: Uint8Array | Buffer | string): Buffer {
  if (typeof body === "string") return Buffer.from(body, "utf-8");
  if (Buffer.isBuffer(body)) return body;
  return Buffer.from(body);
}

export function computeContentDigest(
  body: Uint8Array | Buffer | string,
  algorithm: string = "sha-256",
): string {
  const algoLower = algorithm.toLowerCase();
  const nodeAlgo = SUPPORTED_ALGOS[algoLower];
  if (!nodeAlgo) {
    throw new ContentDigestError(
      `unsupported algorithm ${JSON.stringify(algorithm)}; supported: ${Object.keys(SUPPORTED_ALGOS)}`,
    );
  }
  const hash = createHash(nodeAlgo).update(bodyBytes(body)).digest("base64");
  return `${algoLower}=:${hash}:`;
}

export function verifyContentDigest(
  body: Uint8Array | Buffer | string,
  headerValue: string,
  requireAlgorithm?: string,
): boolean {
  if (typeof headerValue !== "string") {
    throw new ContentDigestError(
      `header must be string, got ${typeof headerValue}`,
    );
  }
  const entries: Array<[string, string]> = [];
  const localRe = new RegExp(DIGEST_ENTRY_RE.source, "g");
  let m: RegExpExecArray | null;
  while ((m = localRe.exec(headerValue)) !== null) {
    entries.push([m[1], m[2]]);
  }
  if (entries.length === 0) {
    throw new ContentDigestError(
      `no valid digest entries in header: ${JSON.stringify(headerValue)}`,
    );
  }

  const reqAlg = requireAlgorithm?.toLowerCase();
  let requiredSeen = false;

  for (const [algo, digestB64] of entries) {
    const algoLower = algo.toLowerCase();
    const nodeAlgo = SUPPORTED_ALGOS[algoLower];
    if (!nodeAlgo) continue;
    if (reqAlg && algoLower === reqAlg) requiredSeen = true;

    let expected: Buffer;
    try {
      expected = Buffer.from(digestB64, "base64");
    } catch (e) {
      throw new ContentDigestError(
        `digest entry ${algoLower} is not valid base64: ${(e as Error).message}`,
      );
    }
    const actual = createHash(nodeAlgo).update(bodyBytes(body)).digest();
    if (!expected.equals(actual)) {
      throw new ContentDigestError(
        `digest mismatch on ${algoLower}: header claims ${digestB64} but body hashes to ${actual.toString("base64")}`,
      );
    }
  }

  if (reqAlg && !requiredSeen) {
    throw new ContentDigestError(
      `required algorithm ${reqAlg} not present in header`,
    );
  }
  return true;
}
