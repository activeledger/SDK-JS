import * as fs from "fs";
import * as path from "path";
import { KeyType } from "@activeledger/sdk-core";
import { KeyHandler } from "../key";
import { NodeCryptoProvider } from "../crypto";

/**
 * Seed-based key derivation, against the published cross-language vectors.
 *
 * The vectors matter more here than usual. Six other SDKs derive keys from
 * the same seeds and phrases, and a derivation that drifts does not fail
 * loudly - it produces a perfectly valid key for an identity that is not the
 * caller's, and the ledger reports 1220 "Signature Incorrect" from somewhere
 * far away.
 */
describe("seed derivation (sdk-node)", () => {
  const handler = new KeyHandler();
  const provider = new NodeCryptoProvider();
  const vectors = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../../../../vectors/seed-vectors.json"), "utf8")
  );

  const seedVectors: any[] = vectors.seedVectors;
  const phraseVectors: any[] = vectors.phraseVectors;

  const valid = seedVectors.filter((v) => v.valid !== false);
  const invalid = seedVectors.filter((v) => v.valid === false);

  it("has vectors for every key type, or it is testing nothing", () => {
    for (const type of ["secp256k1", "ml-dsa-65", "falcon-512"]) {
      expect(valid.some((v) => v.type === type)).toBe(true);
      expect(phraseVectors.some((v) => v.type === type)).toBe(true);
    }
    expect(invalid.length).toBeGreaterThanOrEqual(2);
  });

  it.each(valid.map((v) => [`${v.type}/${v.seedName}${v.publicKeyForm ? "/" + v.publicKeyForm : ""}`, v]))(
    "fromSeed reproduces the published key for %s",
    async (_name, v: any) => {
      const key = await handler.generateKeyFromSeed(
        "k",
        Buffer.from(v.seed, "hex"),
        v.publicKeyForm !== "uncompressed",
        v.type as KeyType
      );

      expect(key.key.pub.pkcs8pem).toBe(v.publicKey);
      expect(key.key.prv.pkcs8pem).toBe(v.privateKey);
      expect(key.type).toBe(v.type);
    }
  );

  it.each(invalid.map((v) => [`${v.type}/${v.seedName}`, v]))(
    "fromSeed REFUSES %s rather than reducing it",
    async (_name, v: any) => {
      // A scalar reduced mod n is a working key for a different identity, and
      // nothing downstream ever reports a problem. Refusing is the whole
      // behaviour being tested.
      await expect(
        handler.generateKeyFromSeed("k", Buffer.from(v.seed, "hex"), true, v.type as KeyType)
      ).rejects.toThrow(/\[1, n-1\]/);
    }
  );

  it.each(
    phraseVectors.map((v) => [
      `${v.type}/${v.phraseName}/${v.scheme}${v.publicKeyForm ? "/" + v.publicKeyForm : ""}`,
      v,
    ])
  )("phrase recovery reproduces the published key for %s", async (_name, v: any) => {
    const key = await handler.restoreBIP39Key("k", v.phrase, {
      compressed: v.publicKeyForm !== "uncompressed",
      passphrase: v.passphrase || undefined,
      legacy: v.scheme === "legacy",
      type: v.type as KeyType,
    });

    expect(key.key.pub.pkcs8pem).toBe(v.publicKey);
    expect(key.key.prv.pkcs8pem).toBe(v.privateKey);
  });

  it("refuses a seed of the wrong length rather than padding it", () => {
    // Padding or truncating would produce a valid key for a different
    // identity - the same failure as reducing a scalar, by another route.
    expect(() => provider.generateFromSeed(new Uint8Array(31), true, KeyType.MLDSA65)).toThrow(/32-byte seed/);
    expect(() => provider.generateFromSeed(new Uint8Array(32), true, KeyType.Falcon512)).toThrow(/48-byte seed/);
    expect(() => provider.generateFromSeed(new Uint8Array(33), true, KeyType.EllipticCurve)).toThrow(/32-byte seed/);
  });

  it("derives a different seed per key type from one phrase", async () => {
    // Domain separation. Without it one phrase gives an ml-dsa-65 seed equal
    // to the secp256k1 scalar, so two identities share entropy.
    const phrase = phraseVectors[0].phrase;
    const keys = await Promise.all(
      [KeyType.EllipticCurve, KeyType.MLDSA65, KeyType.Falcon512].map((type) =>
        handler.restoreBIP39Key("k", phrase, { type })
      )
    );

    const privates = keys.map((k) => k.key.prv.pkcs8pem);
    expect(new Set(privates).size).toBe(3);
  });

  it("a passphrase changes the identity for every key type", async () => {
    for (const type of [KeyType.EllipticCurve, KeyType.MLDSA65, KeyType.Falcon512]) {
      const phrase = phraseVectors[0].phrase;
      const plain = await handler.restoreBIP39Key("k", phrase, { type });
      const withPass = await handler.restoreBIP39Key("k", phrase, { type, passphrase: "TREZOR" });

      expect(plain.key.pub.pkcs8pem).not.toBe(withPass.key.pub.pkcs8pem);
    }
  });

  it("refuses the legacy scheme for a post-quantum type", async () => {
    // Ignoring the flag would hand back a modern-derivation key while the
    // caller believed they were recovering an old one.
    await expect(
      handler.restoreBIP39Key("k", phraseVectors[0].phrase, { type: KeyType.MLDSA65, legacy: true })
    ).rejects.toThrow(/secp256k1 only/);
  });

  it("a seed-derived key signs and verifies for every type", async () => {
    for (const type of [KeyType.EllipticCurve, KeyType.MLDSA65, KeyType.Falcon512]) {
      const seed = Buffer.alloc(type === KeyType.Falcon512 ? 48 : 32, 0x11);
      const key = await handler.generateKeyFromSeed("k", seed, true, type);
      const signature = provider.sign("payload", key.key.prv, type);

      expect(provider.verify("payload", signature, key.key.pub, type)).toBe(true);
    }
  });

  it("the same seed derives the same key every time", async () => {
    const seed = Buffer.alloc(32, 0x5a);
    const a = await handler.generateKeyFromSeed("k", seed, true, KeyType.MLDSA65);
    const b = await handler.generateKeyFromSeed("k", seed, true, KeyType.MLDSA65);

    expect(a.key.prv.pkcs8pem).toBe(b.key.prv.pkcs8pem);
  });
});
