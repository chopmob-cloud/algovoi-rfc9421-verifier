/**
 * RFC 9421 + RFC 9530 verification top-level.
 *
 * Mirror of the Python algovoi_rfc9421_verifier.verify module.
 * Uses @noble/ed25519 for Ed25519 verification.
 */

import * as ed25519 from "@noble/ed25519";

import {
  parseSignatureInput,
  parseSignatureValue,
  SignatureInputParseError,
} from "./parse.js";
import {
  buildSigningBase,
  SigningBaseError,
} from "./signing-base.js";
import {
  verifyContentDigest,
  ContentDigestError,
} from "./content-digest.js";

export class VerifyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerifyError";
  }
}

export type PublicKey = string | Uint8Array;

export interface VerifyResult {
  valid: boolean;
  signature_valid: boolean;
  content_digest_valid: boolean;
  signing_base: string;
  covered_components: string[];
  parameters: Record<string, string | number>;
  label: string;
  errors: string[];
}

export interface VerifyRequestInput {
  method: string;
  authority: string;
  path: string;
  headers: Record<string, string>;
  body: Uint8Array | Buffer | string;
  publicKey: PublicKey;
  scheme?: string;
  requireContentDigest?: boolean;
  requireAlgorithm?: string;
}

function newResult(): VerifyResult {
  return {
    valid: false,
    signature_valid: false,
    content_digest_valid: false,
    signing_base: "",
    covered_components: [],
    parameters: {},
    label: "",
    errors: [],
  };
}

function fail(result: VerifyResult, msg: string): VerifyResult {
  result.errors.push(msg);
  result.valid = false;
  return result;
}

function publicKeyBytes(pk: PublicKey): Uint8Array {
  if (pk instanceof Uint8Array) {
    if (pk.length !== 32) {
      throw new VerifyError(
        `Ed25519 public key must be 32 bytes, got ${pk.length}`,
      );
    }
    return pk;
  }
  if (typeof pk === "string") {
    const hex = pk.startsWith("0x") ? pk.slice(2) : pk;
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new VerifyError("public key hex is invalid");
    }
    if (hex.length !== 64) {
      throw new VerifyError(
        `Ed25519 public key hex must decode to 32 bytes (64 hex chars), got ${hex.length}`,
      );
    }
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  throw new VerifyError("publicKey must be Uint8Array or hex string");
}

export async function verifySignature(
  signingBase: string,
  signatureBytes: Uint8Array,
  publicKey: PublicKey,
  algorithm: string = "ed25519",
): Promise<boolean> {
  if (algorithm.toLowerCase() !== "ed25519") {
    throw new VerifyError(`v0.1.0 supports ed25519 only; got ${algorithm}`);
  }
  if (signatureBytes.length !== 64) {
    throw new VerifyError(
      `Ed25519 signature must be 64 bytes, got ${signatureBytes.length}`,
    );
  }
  const pkBytes = publicKeyBytes(publicKey);
  const messageBytes = new TextEncoder().encode(signingBase);
  try {
    return await ed25519.verifyAsync(signatureBytes, messageBytes, pkBytes);
  } catch {
    return false;
  }
}

export async function verifyRequest(
  input: VerifyRequestInput,
): Promise<VerifyResult> {
  const result = newResult();

  const normHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers)) {
    normHeaders[k.toLowerCase()] = v;
  }

  const siValue = normHeaders["signature-input"];
  if (!siValue) return fail(result, "Signature-Input header missing");
  const sValue = normHeaders["signature"];
  if (!sValue) return fail(result, "Signature header missing");

  let parsedSi;
  try {
    parsedSi = parseSignatureInput(siValue);
  } catch (e) {
    if (e instanceof SignatureInputParseError) {
      return fail(result, `Signature-Input parse error: ${e.message}`);
    }
    throw e;
  }
  result.label = parsedSi.label;
  result.covered_components = parsedSi.covered_components;
  result.parameters = parsedSi.parameters;

  let sigParsed;
  try {
    sigParsed = parseSignatureValue(sValue);
  } catch (e) {
    if (e instanceof SignatureInputParseError) {
      return fail(result, `Signature parse error: ${e.message}`);
    }
    throw e;
  }

  if (
    sigParsed.label &&
    parsedSi.label &&
    sigParsed.label !== parsedSi.label
  ) {
    return fail(
      result,
      `Signature label ${sigParsed.label} does not match Signature-Input label ${parsedSi.label}`,
    );
  }

  const requireCd = input.requireContentDigest ?? true;
  const requireAlg = input.requireAlgorithm ?? "sha-256";

  if (requireCd) {
    const cdHeader = normHeaders["content-digest"];
    if (!cdHeader)
      return fail(result, "Content-Digest header required but missing");
    try {
      verifyContentDigest(input.body, cdHeader, requireAlg);
      result.content_digest_valid = true;
    } catch (e) {
      if (e instanceof ContentDigestError) {
        return fail(result, `Content-Digest verification failed: ${e.message}`);
      }
      throw e;
    }
  } else {
    result.content_digest_valid = true;
  }

  let signingBase: string;
  try {
    signingBase = buildSigningBase({
      coveredComponents: parsedSi.covered_components,
      method: input.method,
      authority: input.authority,
      path: input.path,
      scheme: input.scheme ?? "https",
      headers: normHeaders,
      parameters: parsedSi.parameters,
    });
  } catch (e) {
    if (e instanceof SigningBaseError) {
      return fail(result, `Signing-base build error: ${e.message}`);
    }
    throw e;
  }
  result.signing_base = signingBase;

  const alg = parsedSi.parameters["alg"];
  const algStr = typeof alg === "string" ? alg : "ed25519";

  let sigOk: boolean;
  try {
    sigOk = await verifySignature(
      signingBase,
      sigParsed.signature,
      input.publicKey,
      algStr,
    );
  } catch (e) {
    if (e instanceof VerifyError) {
      return fail(result, `Signature verification setup error: ${e.message}`);
    }
    throw e;
  }

  if (!sigOk) {
    return fail(result, "Ed25519 signature does not verify against signing base");
  }
  result.signature_valid = true;
  result.valid = result.signature_valid && result.content_digest_valid;
  return result;
}
