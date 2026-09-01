import * as crypto from "crypto";
import { WebCryptoProvider } from "../crypto.js";

describe("WebCryptoProvider", () => {
  it("generates a keypair as 0x-prefixed hex", () => {
    const provider = new WebCryptoProvider();
    const key = provider.generate();

    expect(key.prv.pkcs8pem).toMatch(/^0x[0-9a-f]{64}$/);
    // Uncompressed secp256k1 public key: 0x04 prefix + 64 bytes = 65 bytes = 130 hex chars
    expect(key.pub.pkcs8pem).toMatch(/^0x04[0-9a-f]{128}$/);
  });

  it("generates a compressed public key when requested", () => {
    const provider = new WebCryptoProvider();
    const key = provider.generate(true);

    // Compressed secp256k1 public key: 0x02/0x03 prefix + 32 bytes = 33 bytes = 66 hex chars
    expect(key.pub.pkcs8pem).toMatch(/^0x0[23][0-9a-f]{64}$/);
  });

  it("signs and verifies its own signature", () => {
    const provider = new WebCryptoProvider();
    const key = provider.generate();
    const data = JSON.stringify({ hello: "world" });

    const signature = provider.sign(data, key.prv);
    expect(provider.verify(data, signature, key.pub)).toBe(true);
  });

  it("rejects a signature over different data", () => {
    const provider = new WebCryptoProvider();
    const key = provider.generate();

    const signature = provider.sign("original data", key.prv);
    expect(provider.verify("tampered data", signature, key.pub)).toBe(false);
  });

  it("rejects a signature verified against a different key's public key", () => {
    const provider = new WebCryptoProvider();
    const keyA = provider.generate();
    const keyB = provider.generate();
    const data = "some transaction body";

    const signature = provider.sign(data, keyA.prv);
    expect(provider.verify(data, signature, keyB.pub)).toBe(false);
  });

  it("produces distinct keys on repeated calls", () => {
    const provider = new WebCryptoProvider();
    const a = provider.generate();
    const b = provider.generate();

    expect(a.prv.pkcs8pem).not.toBe(b.prv.pkcs8pem);
  });

  it("verifies node:crypto-produced signatures, including high-S ones (regression guard for lowS: false)", () => {
    // @noble/curves' verify() rejects "high-S" signatures by default, but
    // node:crypto (and the ledger itself) never normalizes to low-S when
    // signing - roughly half of all genuinely valid node/ledger signatures
    // would fail here without lowS: false. @noble/curves' own sign() always
    // produces low-S signatures, so a self-signed/self-verified round trip
    // could never catch this regressing - node:crypto is used directly to
    // produce genuine, non-normalized signatures against the same key.
    //
    // Building the node:crypto key via JWK (rather than sdk-node's
    // ASN.1/PEM approach) keeps this package's tests dependency-free of
    // asn1.js, which is sdk-node's concern, not sdk-web's.
    const provider = new WebCryptoProvider();
    const key = provider.generate();

    const toBase64Url = (buf: Buffer) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const privBuf = Buffer.from(key.prv.pkcs8pem.replace(/^0x/, ""), "hex");
    const pubBuf = Buffer.from(key.pub.pkcs8pem.replace(/^0x/, ""), "hex");
    const nodeKey = crypto.createPrivateKey({
      key: {
        kty: "EC",
        crv: "secp256k1",
        d: toBase64Url(privBuf),
        x: toBase64Url(pubBuf.subarray(1, 33)),
        y: toBase64Url(pubBuf.subarray(33, 65)),
      },
      format: "jwk",
    });

    // Which S value comes out is effectively random per signature - 100
    // iterations makes it overwhelmingly likely to hit both low- and
    // high-S at least once, and *every* one must verify.
    for (let i = 0; i < 100; i++) {
      const message = `some transaction body ${i}`;
      const signature = crypto.sign("sha256", Buffer.from(message), nodeKey);
      expect(provider.verify(message, signature.toString("base64"), key.pub)).toBe(true);
    }
  });
});
