import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { KeyType } from "@activeledger/sdk-core";
import { KeyHandler } from "../key.js";
import { WebCryptoProvider } from "../crypto.js";

/**
 * Seed derivation on sdk-web, against the same published vectors sdk-node
 * checks itself against.
 *
 * Both packages must agree byte for byte. They use entirely different
 * primitives - node:crypto against @noble - so agreement here is the only
 * thing proving a phrase recovered in a browser is the same identity as one
 * recovered on a server.
 */
describe("seed derivation (sdk-web)", () => {
  const handler = new KeyHandler();
  const provider = new WebCryptoProvider();
  const here = path.dirname(fileURLToPath(import.meta.url));
  const vectors = JSON.parse(
    fs.readFileSync(path.join(here, "../../../../vectors/seed-vectors.json"), "utf8")
  );

  const seedVectors: any[] = vectors.seedVectors;
  const phraseVectors: any[] = vectors.phraseVectors;
  const valid = seedVectors.filter((v) => v.valid !== false);
  const invalid = seedVectors.filter((v) => v.valid === false);

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
    }
  );

  it.each(invalid.map((v) => [`${v.type}/${v.seedName}`, v]))(
    "fromSeed REFUSES %s rather than reducing it",
    async (_name, v: any) => {
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
    expect(() => provider.generateFromSeed(new Uint8Array(31), true, KeyType.MLDSA65)).toThrow(/32-byte seed/);
    expect(() => provider.generateFromSeed(new Uint8Array(32), true, KeyType.Falcon512)).toThrow(/48-byte seed/);
    expect(() => provider.generateFromSeed(new Uint8Array(33), true, KeyType.EllipticCurve)).toThrow(/32-byte seed/);
  });

  it("refuses the legacy scheme for a post-quantum type", async () => {
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
});
