/**
 * RFC 9421 + RFC 9530 verification top-level.
 *
 * Mirror of the Python algovoi_rfc9421_verifier.verify module.
 * Uses @noble/ed25519 for Ed25519 verification.
 */

import { webcrypto } from "node:crypto";

import * as ed25519 from "@noble/ed25519";

import {
  parseSignatureInput,
  parseSignatureValue,
  SignatureInputParseError,
} from "./parse.js";
import {
  buildSigningBase,
  SigningBaseError,
  type SigningBaseMode,
} from "./signing-base.js";
import {
  verifyContentDigest,
  ContentDigestError,
} from "./content-digest.js";
import { checkFreshness, FreshnessError } from "./freshness.js";
import { checkEd25519PublicKey, WeakKeyError } from "./keycheck.js";

// Node 18 compatibility. @noble/ed25519 v2's async hashing reaches for
// crypto.subtle, which Node 18 does not expose as a global (Node 20+ does).
// Without it verifyAsync throws "crypto.subtle must be defined", which the
// verify path below would otherwise swallow as a failed verification. Provide
// the WebCrypto global when it is absent so verification behaves identically
// across Node 18, 20, and 22.
if (typeof (globalThis as { crypto?: unknown }).crypto === "undefined") {
  (globalThis as { crypto?: unknown }).crypto = webcrypto;
}

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
  requireAlgorithm?: string | null;
  /**
   * Signing-base mode. Default "rfc9421" (v0.3.0+) builds the full
   * RFC 9421 §2.5 signing base, including the mandatory
   * "@signature-params" line, so it verifies any RFC-compliant
   * signer (external fixtures, and the rfc9421_proxy_chain_v1
   * conformance set). This matches the Python verify_request default.
   * Set to "algovoi-v0" for the legacy v0.1.0 base (no
   * "@signature-params" line, @method lowercased) used by the
   * rfc9421_proxy_chain_v0 fixture.
   */
  mode?: SigningBaseMode;

  // --- Sprint A hardening (v0.4.0): freshness / replay / tag / alg ---
  /**
   * Current unix time in seconds. Injected so verification is deterministic in
   * tests and against static fixtures. Defaults to Math.floor(Date.now()/1000).
   */
  now?: number;
  /**
   * Reject when the signed `created` is older than this many seconds. Undefined
   * (the default) disables the age check, which is what keeps long-lived static
   * fixtures valid.
   */
  maxAgeSeconds?: number | null;
  /** Clock-skew tolerance for future-created and past-expires bounds (default 60). */
  maxSkewSeconds?: number;
  /** When true (default), a covered `expires` in the past is rejected. */
  enforceExpires?: boolean;
  /** When true, a signed `created` must be present even if maxAgeSeconds is off. */
  requireCreated?: boolean;
  /** When set, the signature's `tag` parameter must equal this value. */
  expectedTag?: string | null;
  /** When true, a `tag` parameter must be present. */
  requireTag?: boolean;
  /**
   * Allow-list of accepted signature algorithms (lowercased on compare).
   * Defaults to {"ed25519"}. An absent `alg` parameter is always rejected.
   */
  allowedAlgorithms?: Iterable<string>;
  /**
   * Single-use nonce store probe: (nonce, keyid) -> hasBeenSeen. Called only
   * after the signature verifies. A thrown error fails closed (never open).
   */
  nonceSeen?: (nonce: string, keyid: string) => boolean;
  /**
   * Required covered components (RC-1). When set, a signature whose covered set
   * omits any of these (e.g. "@method", "@authority", "@path") is rejected before
   * verification, closing the request-line-rewrite gap where a valid signature
   * over a narrow covered set leaves the rest of the request unsigned and mutable.
   * Case-insensitive. Omit to disable (no behaviour change).
   */
  requiredComponents?: string[];
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
  // Trust-boundary key gate: reject non-canonical, off-curve, and small-order
  // public keys BEFORE verification. @noble/ed25519 (ZIP215) accepts small-order
  // keys, which enables signature-malleability / cross-key classes.
  try {
    checkEd25519PublicKey(pkBytes);
  } catch (e) {
    if (e instanceof WeakKeyError) throw new VerifyError(e.message);
    throw e;
  }
  const messageBytes = new TextEncoder().encode(signingBase);
  try {
    return await ed25519.verifyAsync(signatureBytes, messageBytes, pkBytes);
  } catch (e) {
    // A crypto-setup error (e.g. missing crypto.subtle) must not be silently
    // reported as an invalid signature. Surface it as VerifyError; only a
    // genuine verification mismatch returns false.
    if (
      e instanceof Error &&
      /crypto\.subtle|subtle must be defined/i.test(e.message)
    ) {
      throw new VerifyError(e.message);
    }
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

  // RC-1: caller policy on covered-component completeness. A signature over a
  // narrow covered set is cryptographically valid but may omit request-line
  // components (@method/@authority/@path); when the caller pins a required set, a
  // signature omitting any of them is rejected here rather than trusting a
  // narrowly-scoped signature over a rewritten request line. The covered list is
  // still returned either way. (Parity with the Python verifier.)
  if (input.requiredComponents && input.requiredComponents.length > 0) {
    const covered = new Set(
      parsedSi.covered_components.map((c) =>
        c.trim().replace(/^"+|"+$/g, "").toLowerCase(),
      ),
    );
    const missing = input.requiredComponents.filter(
      (c) => !covered.has(c.trim().toLowerCase()),
    );
    if (missing.length > 0) {
      const repr = missing
        .slice()
        .sort()
        .map((s) => `'${s}'`)
        .join(", ");
      return fail(result, `required covered components missing: [${repr}]`);
    }
  }

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

  // Freshness / replay window (item 1). Runs before the cryptographic check so
  // a stale or expired signature is rejected regardless of whether its bytes
  // would verify. Only covered (signed) created/expires are trusted; see
  // freshness.ts.
  const now = input.now ?? Math.floor(Date.now() / 1000);
  const mode: SigningBaseMode = input.mode ?? "rfc9421";
  try {
    checkFreshness(parsedSi.parameters, parsedSi.covered_components, {
      now,
      maxAgeSeconds: input.maxAgeSeconds,
      maxSkewSeconds: input.maxSkewSeconds,
      enforceExpires: input.enforceExpires,
      requireCreated: input.requireCreated,
      // In rfc9421 mode @signature-params (with created/expires) is signed, so
      // those params are trustworthy even if not covered components.
      paramsSigned: mode === "rfc9421",
    });
  } catch (e) {
    if (e instanceof FreshnessError) {
      return fail(result, `Freshness check failed: ${e.message}`);
    }
    throw e;
  }

  // Anti cross-protocol reuse via the RFC 9421 `tag` parameter (item 2). `tag`
  // rides inside @signature-params, which is signed verbatim, so a present tag
  // is already cryptographically bound; here we enforce the caller's policy.
  const tagValue = parsedSi.parameters["tag"];
  if (input.requireTag && tagValue === undefined) {
    return fail(result, "Signature 'tag' parameter required but absent");
  }
  if (
    input.expectedTag !== undefined &&
    input.expectedTag !== null &&
    tagValue !== input.expectedTag
  ) {
    return fail(
      result,
      `Signature 'tag' ${JSON.stringify(tagValue)} does not match expected ${JSON.stringify(input.expectedTag)}`,
    );
  }

  const requireCd = input.requireContentDigest ?? true;
  // string = enforce that specific algorithm; null or undefined = accept any
  // supported algorithm present in the Content-Digest header (SHA-256 or
  // SHA-512 in this v0.2.x). Default is permissive.
  const requireAlg: string | undefined =
    input.requireAlgorithm == null ? undefined : input.requireAlgorithm;

  if (requireCd) {
    const cdHeader = normHeaders["content-digest"];
    if (!cdHeader)
      return fail(result, "Content-Digest header required but missing");
    // RC-2 body integrity: content-digest must be a COVERED component. Otherwise
    // an attacker swaps the body + recomputes a matching CD header and the
    // signature (which never covered CD) still verifies. Matching the CD to the
    // body is necessary but not sufficient; it must also be signed. (Parity with
    // the Python verifier; caught by rfc9421_hardening_v1 content_digest_not_covered.)
    const coveredLower = parsedSi.covered_components.map((c) =>
      c.trim().replace(/^"+|"+$/g, "").toLowerCase(),
    );
    if (!coveredLower.includes("content-digest")) {
      return fail(
        result,
        "Content-Digest required but not a covered signature component",
      );
    }
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
      mode,
      signatureParamsRaw:
        mode === "rfc9421" ? parsedSi.params_block : undefined,
    });
  } catch (e) {
    if (e instanceof SigningBaseError) {
      return fail(result, `Signing-base build error: ${e.message}`);
    }
    throw e;
  }
  result.signing_base = signingBase;

  // Algorithm-downgrade hardening (item 3). Do NOT default a missing alg to
  // ed25519: an absent alg is ambiguous and a downgrade-by-omission vector, so
  // reject it. Then pin the alg to the caller's allow-list before verifying.
  const alg = parsedSi.parameters["alg"];
  if (alg === undefined) {
    return fail(result, "Signature-Input missing 'alg' parameter");
  }
  if (typeof alg !== "string") {
    return fail(
      result,
      `Signature-Input 'alg' parameter must be string, got ${typeof alg}`,
    );
  }
  const allowedAlgorithms = input.allowedAlgorithms ?? ["ed25519"];
  const allowedLower = new Set<string>();
  for (const a of allowedAlgorithms) {
    allowedLower.add(String(a).toLowerCase());
  }
  if (!allowedLower.has(alg.toLowerCase())) {
    const sorted = Array.from(allowedLower).sort();
    return fail(
      result,
      `Signature algorithm ${JSON.stringify(alg)} is not in the allowed set [${sorted.map((s) => JSON.stringify(s)).join(", ")}]`,
    );
  }

  let sigOk: boolean;
  try {
    sigOk = await verifySignature(
      signingBase,
      sigParsed.signature,
      input.publicKey,
      alg,
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

  // Single-use nonce / replay check (item 1). Deferred until after the
  // signature verifies so the caller's store is only ever probed with an
  // authentic message, not attacker-supplied junk. This library stays
  // stateless and only asks "has this (nonce, keyid) been seen?".
  if (input.nonceSeen !== undefined) {
    const nonceValue = parsedSi.parameters["nonce"];
    if (nonceValue !== undefined) {
      const keyidValue = String(parsedSi.parameters["keyid"] ?? "");
      let already: boolean;
      try {
        already = input.nonceSeen(String(nonceValue), keyidValue);
      } catch (e) {
        // A store failure must fail closed, not open.
        return fail(
          result,
          `Nonce store check errored: ${(e as Error).message}`,
        );
      }
      if (already) {
        return fail(result, "Signature nonce has already been used (replay)");
      }
    }
  }

  result.valid = result.signature_valid && result.content_digest_valid;
  return result;
}
