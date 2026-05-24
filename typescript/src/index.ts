/**
 * @algovoi/rfc9421-verifier
 *
 * AlgoVoi RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest
 * reference verifier (TypeScript). Byte-for-byte parity with the
 * Python sibling `algovoi-rfc9421-verifier` on PyPI.
 *
 * Apache 2.0. Companion to IETF Internet-Draft
 * draft-hopley-x402-compliance-receipt-00.
 */

export {
  SignatureInputParseError,
  parseSignatureInput,
  parseSignatureValue,
  type ParsedSignatureInput,
} from "./parse.js";

export {
  SigningBaseError,
  buildSigningBase,
  type SigningBaseInput,
} from "./signing-base.js";

export {
  ContentDigestError,
  computeContentDigest,
  verifyContentDigest,
} from "./content-digest.js";

export {
  VerifyError,
  verifySignature,
  verifyRequest,
  type VerifyResult,
  type VerifyRequestInput,
  type PublicKey,
} from "./verify.js";
