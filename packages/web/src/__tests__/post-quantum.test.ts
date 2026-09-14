import { WebCryptoProvider } from "../crypto.js";

/**
 * Post-quantum keys in sdk-web.
 *
 * The cross-package check - a web key verifying in node and the reverse -
 * is scripts/verify-pq-interop.mjs rather than a case here. Jest's ESM
 * runtime refuses to load sdk-node's CommonJS build because it require()s
 * ESM, which Node itself has done happily since 20.19. Testing the built
 * artifacts under plain node checks what actually ships instead of what
 * Jest's module registry can be persuaded to load.
 */
const PQ_TYPES = ["ml-dsa-65", "falcon-512"];

describe("WebCryptoProvider - post-quantum", () => {
  const web = new WebCryptoProvider();

  it("still defaults to secp256k1 when no type is given", () => {
    const keys = web.generate();
    expect(keys.pub.pkcs8pem.startsWith("0x")).toBe(true);
    const data = JSON.stringify({ $i: { alice: {} } });
    expect(web.verify(data, web.sign(data, keys.prv), keys.pub)).toBe(true);
  });

  for (const type of PQ_TYPES) {
    describe(type, () => {
      it("signs and verifies", () => {
        const keys = web.generate(false, type);
        const data = JSON.stringify({ $i: { alice: { amount: "100" } } });
        expect(web.verify(data, web.sign(data, keys.prv, type), keys.pub, type)).toBe(true);
      });

      it("rejects a tampered payload", () => {
        const keys = web.generate(false, type);
        const sig = web.sign(JSON.stringify({ amount: "100" }), keys.prv, type);
        expect(web.verify(JSON.stringify({ amount: "999" }), sig, keys.pub, type)).toBe(false);
      });

      it("returns false rather than throwing on junk", () => {
        const keys = web.generate(false, type);
        expect(web.verify("tx", "not-a-signature", keys.pub, type)).toBe(false);
      });
    });
  }
});
