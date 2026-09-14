import { NodeCryptoProvider } from "../crypto";
import { KeyType, POST_QUANTUM_KEY_TYPES } from "@activeledger/sdk-core";

/**
 * Post-quantum keys in sdk-node.
 *
 * The cross-package test that matters most - a key generated here verifying
 * in sdk-web and the reverse - lives in packages/web, because that suite runs
 * under ESM where both providers can be loaded together.
 */
describe("NodeCryptoProvider - post-quantum", () => {
  const crypto = new NodeCryptoProvider();

  it("still defaults to secp256k1 when no type is given", () => {
    const keys = crypto.generate();
    expect(keys.pub.pkcs8pem.startsWith("0x")).toBe(true);
    const data = JSON.stringify({ $i: { alice: {} } });
    expect(crypto.verify(data, crypto.sign(data, keys.prv), keys.pub)).toBe(true);
  });

  for (const type of POST_QUANTUM_KEY_TYPES) {
    describe(type, () => {
      it("generates base64 keys, not 0x hex", () => {
        const keys = crypto.generate(false, type);
        expect(keys.pub.pkcs8pem.startsWith("0x")).toBe(false);
        expect(Buffer.from(keys.pub.pkcs8pem, "base64").length).toBeGreaterThan(800);
      });

      it("signs and verifies", () => {
        const keys = crypto.generate(false, type);
        const data = JSON.stringify({ $i: { alice: { amount: "100" } } });
        expect(crypto.verify(data, crypto.sign(data, keys.prv, type), keys.pub, type)).toBe(true);
      });

      it("rejects a signature over different data", () => {
        const keys = crypto.generate(false, type);
        const sig = crypto.sign(JSON.stringify({ amount: "100" }), keys.prv, type);
        expect(crypto.verify(JSON.stringify({ amount: "101" }), sig, keys.pub, type)).toBe(false);
      });

      it("rejects another key's signature", () => {
        const mine = crypto.generate(false, type);
        const theirs = crypto.generate(false, type);
        const data = "tx";
        expect(crypto.verify(data, crypto.sign(data, mine.prv, type), theirs.pub, type)).toBe(false);
      });

      it("returns false rather than throwing on junk", () => {
        const keys = crypto.generate(false, type);
        expect(crypto.verify("tx", "not-a-signature", keys.pub, type)).toBe(false);
        expect(crypto.verify("tx", "", keys.pub, type)).toBe(false);
      });

      it("will not verify the other scheme's signature", () => {
        const other = POST_QUANTUM_KEY_TYPES.filter((t) => t !== type)[0];
        const keys = crypto.generate(false, type);
        const otherKeys = crypto.generate(false, other);
        const data = "tx";
        expect(crypto.verify(data, crypto.sign(data, otherKeys.prv, other), keys.pub, type)).toBe(false);
      });

      it("round-trips non-ASCII payloads", () => {
        const keys = crypto.generate(false, type);
        const data = JSON.stringify({ note: "café 日本語 🔐" });
        expect(crypto.verify(data, crypto.sign(data, keys.prv, type), keys.pub, type)).toBe(true);
      });
    });
  }

  it("ml-dsa-65 signature length is fixed, falcon-512's is not", () => {
    const lengths: Record<string, Set<number>> = {};
    for (const type of POST_QUANTUM_KEY_TYPES) {
      const keys = crypto.generate(false, type);
      lengths[type] = new Set();
      for (let i = 0; i < 30; i++) {
        lengths[type].add(Buffer.from(crypto.sign("tx" + i, keys.prv, type), "base64").length);
      }
    }
    expect(lengths[KeyType.MLDSA65].size).toBe(1);
    expect(lengths[KeyType.Falcon512].size).toBeGreaterThan(1);
  });
});
