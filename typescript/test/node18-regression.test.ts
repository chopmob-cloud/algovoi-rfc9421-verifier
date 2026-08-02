/**
 * Regression for the Node 18 crypto.subtle bug.
 *
 * On Node 18, @noble/ed25519 v2's async verification reaches for crypto.subtle,
 * which Node 18 does not expose as a global, so verifyAsync throws
 * "crypto.subtle must be defined". Before the fix, verifySignature swallowed
 * that as `false`, so VALID signatures silently failed to verify. The module
 * now installs a WebCrypto shim on import, and a crypto-setup error is surfaced
 * rather than reported as a bad signature.
 *
 * This test must pass on Node 18, 20, and 22.
 */
import { describe, expect, it } from "vitest";
import * as ed from "@noble/ed25519";

import { verifySignature } from "../src/index.js";

// A fixed deterministic Ed25519 test seed (not RFC 8032 Test 1).
const SEED = new Uint8Array(
  Buffer.from(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55",
    "hex",
  ),
);

describe("Node 18 crypto.subtle regression", () => {
  it("verifies a valid signature instead of silently returning false", async () => {
    const pub = await ed.getPublicKeyAsync(SEED);
    const base = "node18-regression signing base";
    const sig = await ed.signAsync(new TextEncoder().encode(base), SEED);
    await expect(verifySignature(base, sig, pub)).resolves.toBe(true);
  });

  it("still returns false for a tampered signature", async () => {
    const pub = await ed.getPublicKeyAsync(SEED);
    const sig = await ed.signAsync(new TextEncoder().encode("base"), SEED);
    sig[0] ^= 0x01;
    await expect(verifySignature("base", sig, pub)).resolves.toBe(false);
  });
});
