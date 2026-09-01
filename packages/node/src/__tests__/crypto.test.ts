import { NodeCryptoProvider } from "../crypto";

describe("NodeCryptoProvider", () => {
  it("generates a keypair as 0x-prefixed hex", () => {
    const provider = new NodeCryptoProvider();
    const key = provider.generate();

    expect(key.prv.pkcs8pem).toMatch(/^0x[0-9a-f]{64}$/);
    // Uncompressed secp256k1 public key: 0x04 prefix + 64 bytes = 65 bytes = 130 hex chars
    expect(key.pub.pkcs8pem).toMatch(/^0x04[0-9a-f]{128}$/);
  });

  it("generates a compressed public key when requested", () => {
    const provider = new NodeCryptoProvider();
    const key = provider.generate(true);

    // Compressed secp256k1 public key: 0x02/0x03 prefix + 32 bytes = 33 bytes = 66 hex chars
    expect(key.pub.pkcs8pem).toMatch(/^0x0[23][0-9a-f]{64}$/);
  });

  it("signs and verifies its own signature", () => {
    const provider = new NodeCryptoProvider();
    const key = provider.generate();
    const data = JSON.stringify({ hello: "world" });

    const signature = provider.sign(data, key.prv);
    expect(provider.verify(data, signature, key.pub)).toBe(true);
  });

  it("rejects a signature over different data", () => {
    const provider = new NodeCryptoProvider();
    const key = provider.generate();

    const signature = provider.sign("original data", key.prv);
    expect(provider.verify("tampered data", signature, key.pub)).toBe(false);
  });

  it("rejects a signature verified against a different key's public key", () => {
    const provider = new NodeCryptoProvider();
    const keyA = provider.generate();
    const keyB = provider.generate();
    const data = "some transaction body";

    const signature = provider.sign(data, keyA.prv);
    expect(provider.verify(data, signature, keyB.pub)).toBe(false);
  });

  it("produces distinct keys on repeated calls", () => {
    const provider = new NodeCryptoProvider();
    const a = provider.generate();
    const b = provider.generate();

    expect(a.prv.pkcs8pem).not.toBe(b.prv.pkcs8pem);
  });
});
