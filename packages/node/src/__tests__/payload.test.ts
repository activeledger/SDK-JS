import { PayloadHandler } from "../payload";
import { KeyHandler } from "../key";
import { KeyType } from "@activeledger/sdk-core";

/**
 * Signing an arbitrary payload - an exchange order, an attestation, an auth
 * challenge - rather than a transaction.
 *
 * Possible before by instantiating the platform's crypto provider, but that
 * was the one thing in this SDK that could not be written once: every other
 * public class is named the same in both packages, and the providers are not.
 */
describe("PayloadHandler", () => {
  const payload = new PayloadHandler();
  const keys = new KeyHandler();
  const TYPES = [KeyType.EllipticCurve, KeyType.Falcon512, KeyType.MLDSA65];

  for (const type of TYPES) {
    describe(type, () => {
      it("signs and verifies an object", async () => {
        const key = await keys.generateKey("maker", false, type);
        const order = { pair: "VNR/USDT", side: "sell", amount: "100" };
        const sig = payload.sign(order, key);
        expect(payload.verify(order, sig, key.key.pub.pkcs8pem, key.type)).toBe(true);
      });

      it("verifies the canonical string identically to the object", async () => {
        const key = await keys.generateKey("maker", false, type);
        const order = { pair: "VNR/USDT", amount: "100" };
        const sig = payload.sign(order, key);
        expect(payload.verify(payload.canonical(order), sig, key.key.pub.pkcs8pem, key.type)).toBe(true);
      });

      it("rejects a tampered payload", async () => {
        const key = await keys.generateKey("maker", false, type);
        const order = { amount: "100" };
        const sig = payload.sign(order, key);
        expect(payload.verify({ amount: "999" }, sig, key.key.pub.pkcs8pem, key.type)).toBe(false);
      });

      it("rejects another key's signature", async () => {
        const mine = await keys.generateKey("mine", false, type);
        const theirs = await keys.generateKey("theirs", false, type);
        const order = { amount: "100" };
        expect(
          payload.verify(order, payload.sign(order, mine), theirs.key.pub.pkcs8pem, type)
        ).toBe(false);
      });

      it("returns false rather than throwing on junk", async () => {
        const key = await keys.generateKey("maker", false, type);
        expect(payload.verify({ a: 1 }, "not-a-signature", key.key.pub.pkcs8pem, type)).toBe(false);
        expect(payload.verify({ a: 1 }, "", key.key.pub.pkcs8pem, type)).toBe(false);
      });
    });
  }

  it("canonical() is the exact string that gets signed", () => {
    expect(payload.canonical({ b: 2, a: 1 })).toBe('{"b":2,"a":1}');
    // A string is already canonical - passing one back through is a no-op,
    // which is what makes "store the canonical form and verify that" work.
    expect(payload.canonical('{"b":2,"a":1}')).toBe('{"b":2,"a":1}');
  });

  it("shows why canonical() exists: key order changes the bytes", async () => {
    // The hazard this API is meant to make avoidable. Same fields, different
    // insertion order, and the signature does not verify - which presents as
    // a bad signature rather than an encoding problem.
    const key = await keys.generateKey("maker", false, KeyType.Falcon512);
    const signedAs = { pair: "VNR/USDT", side: "sell" };
    const rebuiltAs = { side: "sell", pair: "VNR/USDT" };
    const sig = payload.sign(signedAs, key);

    expect(payload.canonical(signedAs)).not.toBe(payload.canonical(rebuiltAs));
    expect(payload.verify(rebuiltAs, sig, key.key.pub.pkcs8pem, key.type)).toBe(false);
    // ...and the way to be safe from it: keep the string, verify the string.
    const exact = payload.canonical(signedAs);
    expect(payload.verify(exact, sig, key.key.pub.pkcs8pem, key.type)).toBe(true);
  });

  it("defaults to secp256k1 when no type is given", async () => {
    const key = await keys.generateKey("maker");
    const order = { a: 1 };
    // No type argument anywhere - the old default path still works.
    expect(payload.verify(order, payload.sign(order, key), key.key.pub.pkcs8pem)).toBe(true);
  });
});
