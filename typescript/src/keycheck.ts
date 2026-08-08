/**
 * Ed25519 public-key validation for the verifier's trust boundary.
 *
 * Byte-for-byte mirror of the Python algovoi_rfc9421_verifier.keycheck module.
 * Rejects, fail-closed and BEFORE signature verification:
 *   1. non-canonical encodings (y >= p) and points not on the curve;
 *   2. small-order points (order dividing the cofactor 8, incl. the identity).
 *
 * @noble/ed25519 under its default ZIP215 rules accepts small-order public keys;
 * for an audited offline verifier that treats the resolved key as the trust
 * anchor we reject them. Small-order-ness is derived mathematically
 * ([8]P == identity) using RFC 8032 Appendix A arithmetic — no hard-coded
 * blocklist.
 */

const P = 2n ** 255n - 19n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = base % m;
  if (b < 0n) b += m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function modInv(a: bigint): bigint {
  return modPow(mod(a), P - 2n, P);
}

const D = mod(-121665n * modInv(121666n));
const SQRT_M1 = modPow(2n, (P - 1n) / 4n, P);

// Extended homogeneous coordinates (X, Y, Z, T).
type Point = [bigint, bigint, bigint, bigint];

export class WeakKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WeakKeyError";
  }
}

function recoverX(y: bigint, sign: number): bigint | null {
  if (y >= P) return null; // non-canonical y encoding
  const x2 = mod((y * y - 1n) * modInv(mod(D * y * y + 1n)));
  if (x2 === 0n) return sign ? null : 0n;
  let x = modPow(x2, (P + 3n) / 8n, P);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return null; // not a square -> off curve
  if (Number(x & 1n) !== sign) x = P - x;
  return x;
}

function decode(pk: Uint8Array): Point | null {
  if (pk.length !== 32) return null;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(pk[i]); // little-endian
  const sign = Number((y >> 255n) & 1n);
  y &= (1n << 255n) - 1n;
  const x = recoverX(y, sign);
  if (x === null) return null;
  return [x, y, 1n, mod(x * y)];
}

function add(p: Point, q: Point): Point {
  const A = mod((p[1] - p[0]) * (q[1] - q[0]));
  const B = mod((p[1] + p[0]) * (q[1] + q[0]));
  const C = mod(2n * p[3] * q[3] * D);
  const Dd = mod(2n * p[2] * q[2]);
  const E = B - A;
  const F = Dd - C;
  const G = Dd + C;
  const H = B + A;
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}

function mul8(p: Point): Point {
  const p2 = add(p, p);
  const p4 = add(p2, p2);
  return add(p4, p4);
}

function isIdentity(p: Point): boolean {
  return mod(p[0]) === 0n && mod(p[1] - p[2]) === 0n;
}

/** True iff pk decodes to a point whose order divides 8 (incl. identity). */
export function isSmallOrder(pk: Uint8Array): boolean {
  const p = decode(pk);
  if (p === null) return false;
  return isIdentity(mul8(p));
}

/** Throw WeakKeyError if pk is non-canonical, off-curve, or small-order. */
export function checkEd25519PublicKey(pk: Uint8Array): void {
  const p = decode(pk);
  if (p === null) {
    throw new WeakKeyError("public key is not a canonical on-curve Ed25519 point");
  }
  if (isIdentity(mul8(p))) {
    throw new WeakKeyError("public key is a small-order Ed25519 point");
  }
}
