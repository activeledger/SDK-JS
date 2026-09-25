import * as crypto from "crypto";
import { NodeCryptoProvider } from "../crypto";

/**
 * sdk-node must never emit a high-S signature.
 *
 * Not for the ledger, which verifies through OpenSSL and accepts either.
 * For everything else: @noble/curves - which sdk-web signs and verifies with
 * - rejects high-S unless explicitly told not to, as do libsecp256k1 and
 * Rust's k256. Before this was fixed, sdk-node emitted high-S roughly half
 * the time, so a signature made in Node failed against such a verifier about
 * half the time. That presents as intermittent auth trouble rather than as a
 * signature format problem, and it cost one team a live bug.
 */

const SECP256K1_N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);
const HALF_N = SECP256K1_N / BigInt(2);

/** Pulls S out of a base64 DER signature. */
function signatureS(base64: string): bigint {
  const der = Buffer.from(base64, "base64");
  let offset = 2;
  offset += 2 + der[offset + 1]; // skip R
  const length = der[offset + 1];

  return BigInt("0x" + der.subarray(offset + 2, offset + 2 + length).toString("hex"));
}

const isHighS = (base64: string): boolean => signatureS(base64) > HALF_N;

describe("sdk-node secp256k1 signatures are canonical", () => {
  const provider = new NodeCryptoProvider();

  it("never emits a high-S signature", () => {
    const key = provider.generate(true, "secp256k1");

    for (let i = 0; i < 300; i++) {
      const signature = provider.sign(`message ${i}`, key.prv, "secp256k1");
      expect(isHighS(signature)).toBe(false);
    }
  });

  it("still verifies everything it produces", () => {
    const key = provider.generate(true, "secp256k1");

    for (let i = 0; i < 50; i++) {
      const signature = provider.sign(`message ${i}`, key.prv, "secp256k1");
      expect(provider.verify(`message ${i}`, signature, key.pub, "secp256k1")).toBe(true);
    }
  });

  // The other half of the rule. The ledger still signs through OpenSSL
  // without normalising, so high-S signatures remain a real thing to meet;
  // rejecting them would be the same bug pointed the other way.
  it("still ACCEPTS a high-S signature from elsewhere", () => {
    const key = provider.generate(true, "secp256k1");
    const signature = provider.sign("payload", key.prv, "secp256k1");

    // Negate s: still valid over the same message under the same key.
    const der = Buffer.from(signature, "base64");
    let offset = 2;
    const rLength = der[offset + 1];
    const r = der.subarray(offset + 2, offset + 2 + rLength);
    offset += 2 + rLength;
    const s = signatureS(signature);

    const negated = Buffer.from((SECP256K1_N - s).toString(16).padStart(64, "0"), "hex");
    const derInteger = (value: Buffer): Buffer => {
      let trimmed = value;
      let start = 0;
      while (start < trimmed.length - 1 && trimmed[start] === 0) start++;
      trimmed = trimmed.subarray(start);
      if (trimmed[0] & 0x80) trimmed = Buffer.concat([Buffer.from([0]), trimmed]);
      return Buffer.concat([Buffer.from([0x02, trimmed.length]), trimmed]);
    };
    const body = Buffer.concat([derInteger(r), derInteger(negated)]);
    const highS = Buffer.concat([Buffer.from([0x30, body.length]), body]).toString("base64");

    expect(isHighS(highS)).toBe(true);
    expect(highS).not.toEqual(signature);
    expect(provider.verify("payload", highS, key.pub, "secp256k1")).toBe(true);
    // Permissive about s only.
    expect(provider.verify("tampered", highS, key.pub, "secp256k1")).toBe(false);
  });
  /**
   * Low-S folding is a secp256k1 canonicalisation: it reads the signature as
   * a DER (r, s) pair. An RSA signature is a single integer, so folding one
   * threw "Malformed ECDSA signature: expected R" and broke RSA signing
   * outright - which is what some contract-deploy identities use, so every
   * deploy failed. `generate()` cannot make an RSA key (it ignores any
   * non-post-quantum type and returns secp256k1), so the key here is a real
   * one from node:crypto, which is also the shape a legacy RSA identity has.
   */
  it("signs and verifies with an RSA key, which is not an (r, s) pair", () => {
    const provider = new NodeCryptoProvider();
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const signature = provider.sign("payload", { pkcs8pem: privateKey }, "rsa");

    expect(Buffer.from(signature, "base64").length).toBe(256);
    expect(provider.verify("payload", signature, { pkcs8pem: publicKey }, "rsa")).toBe(true);
    expect(provider.verify("tampered", signature, { pkcs8pem: publicKey }, "rsa")).toBe(false);
  });

  it("signs with an RSA key when no type is passed", () => {
    const provider = new NodeCryptoProvider();
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const signature = provider.sign("payload", { pkcs8pem: privateKey });

    expect(provider.verify("payload", signature, { pkcs8pem: publicKey })).toBe(true);
  });
});
