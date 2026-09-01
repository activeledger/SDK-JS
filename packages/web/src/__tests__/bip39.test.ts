import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { KeyHandler } from "../key.js";

describe("KeyHandler BIP-39 (sdk-web)", () => {
  const handler = new KeyHandler();

  // Official BIP-39 test vector (12 words, empty passphrase):
  // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
  const TEST_PHRASE = "legal winner thank year wave sausage worth useful legal winner thank yellow";

  it("default mode is deterministic - the same phrase always derives the same key", async () => {
    const a = await handler.restoreBIP39Key("k", TEST_PHRASE);
    const b = await handler.restoreBIP39Key("k", TEST_PHRASE);
    expect(a.key.prv.pkcs8pem).toBe(b.key.prv.pkcs8pem);
    expect(a.key.prv.pkcs8pem).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("legacy mode is deterministic and differs from default mode for the same phrase", async () => {
    const legacy = await handler.restoreBIP39Key("k", TEST_PHRASE, { legacy: true });
    const legacyAgain = await handler.restoreBIP39Key("k", TEST_PHRASE, { legacy: true });
    const standard = await handler.restoreBIP39Key("k", TEST_PHRASE);

    expect(legacy.key.prv.pkcs8pem).toBe(legacyAgain.key.prv.pkcs8pem);
    expect(legacy.key.prv.pkcs8pem).not.toBe(standard.key.prv.pkcs8pem);
    expect(legacy.key.prv.pkcs8pem).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("an optional passphrase changes the derived key in default mode", async () => {
    const noPassphrase = await handler.restoreBIP39Key("k", TEST_PHRASE);
    const withPassphrase = await handler.restoreBIP39Key("k", TEST_PHRASE, { passphrase: "extra" });
    expect(noPassphrase.key.prv.pkcs8pem).not.toBe(withPassphrase.key.prv.pkcs8pem);
  });

  it("generateBIP39Key produces a fresh, valid mnemonic each time", async () => {
    const a = await handler.generateBIP39Key("k");
    const b = await handler.generateBIP39Key("k");
    expect(a.phrase).not.toBe(b.phrase);
    expect(a.phrase!.split(" ")).toHaveLength(12);
    expect(a.key.prv.pkcs8pem).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("compressed option produces a compressed pubkey for BIP-39-derived keys", async () => {
    const compressed = await handler.restoreBIP39Key("k", TEST_PHRASE, { compressed: true });
    expect(compressed.key.pub.pkcs8pem).toMatch(/^0x0[23][0-9a-f]{64}$/);
  });

  it("BIP-32 master-key derivation matches the official BIP-32 test vector 1", () => {
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
    const seed = new Uint8Array(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    const master = hmac(sha512, new TextEncoder().encode("Bitcoin seed"), seed).subarray(0, 32);
    const hex = Array.from(master)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
  });
});
