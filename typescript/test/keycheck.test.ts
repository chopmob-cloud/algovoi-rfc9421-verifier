/**
 * Tests for the Ed25519 public-key trust-boundary gate (keycheck) — mirrors the
 * Python tests/test_keycheck.py so the two implementations behave identically.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { createHash } from "node:crypto";
import {
  WeakKeyError,
  checkEd25519PublicKey,
  isSmallOrder,
  verifyRequest,
} from "../src/index.js";

// @noble/ed25519 v2 needs SHA-512 wired for sync getPublicKey in Node.
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = createHash("sha512");
  for (const x of m) h.update(x);
  return new Uint8Array(h.digest());
};

function hex(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "hex"));
}

// Small-order encodings (little-endian), orders 1, 2, 4.
const IDENTITY = hex("0100000000000000000000000000000000000000000000000000000000000000");
const ORDER2_NEG1 = hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
const ORDER4_YZERO = hex("0000000000000000000000000000000000000000000000000000000000000000");
const ORDER4_YZERO_HI = hex("0000000000000000000000000000000000000000000000000000000000000080");
const SMALL_ORDER = [IDENTITY, ORDER2_NEG1, ORDER4_YZERO, ORDER4_YZERO_HI];

const NONCANONICAL_Y_EQ_P = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
const RFC8032_TEST1_PUB = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

describe("keycheck: small-order rejection", () => {
  for (const pk of SMALL_ORDER) {
    it(`rejects small-order point ${Buffer.from(pk).toString("hex").slice(0, 8)}…`, () => {
      expect(isSmallOrder(pk)).toBe(true);
      expect(() => checkEd25519PublicKey(pk)).toThrow(WeakKeyError);
    });
  }

  it("rejects a non-canonical (y == p) encoding", () => {
    expect(() => checkEd25519PublicKey(NONCANONICAL_Y_EQ_P)).toThrow(WeakKeyError);
  });

  it("rejects wrong-length input", () => {
    expect(() => checkEd25519PublicKey(new Uint8Array(31))).toThrow(WeakKeyError);
  });
});

describe("keycheck: valid keys accepted", () => {
  it("accepts the RFC 8032 Test 1 public key", () => {
    expect(() => checkEd25519PublicKey(RFC8032_TEST1_PUB)).not.toThrow();
    expect(isSmallOrder(RFC8032_TEST1_PUB)).toBe(false);
  });

  it("accepts a large sample of genuine keys", () => {
    for (let i = 0; i < 200; i++) {
      const pk = ed.getPublicKey(new Uint8Array(32).fill(i % 256));
      expect(() => checkEd25519PublicKey(pk)).not.toThrow();
      expect(isSmallOrder(pk)).toBe(false);
    }
  });
});

describe("keycheck: fails closed end-to-end", () => {
  it("verifyRequest returns invalid for a small-order public key", async () => {
    const r = await verifyRequest({
      method: "POST",
      authority: "api.algovoi.co.uk",
      path: "/a2a",
      headers: {
        "signature-input": 'sig=("@method");created=1750000000;keyid="k";alg="ed25519"',
        signature: "sig=:" + "A".repeat(86) + "==:",
        "content-digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
      },
      body: new Uint8Array(0),
      publicKey: IDENTITY,
      requireContentDigest: false,
    });
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /small-order|canonical/.test(e))).toBe(true);
  });
});
