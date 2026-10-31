import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { KeyType } from "@activeledger/sdk-core";
import * as recovery from "../recovery.js";
import { KeyHandler } from "../key.js";

/**
 * The public recovery module on sdk-web.
 *
 * sdk-node uses node:crypto and sdk-web uses @noble - entirely different
 * primitives - so agreement here is what proves a seed derived in a browser
 * is the same identity as one derived on a server.
 */
describe("recovery (sdk-web)", () => {
  const handler = new KeyHandler();
  const here = path.dirname(fileURLToPath(import.meta.url));
  const vectors = JSON.parse(
    fs.readFileSync(path.join(here, "../../../../vectors/seed-vectors.json"), "utf8")
  );
  const phraseVectors: any[] = vectors.phraseVectors;

  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

  it.each(phraseVectors.filter((v) => v.scheme === "v1").map((v) => [`${v.type}/${v.phraseName}`, v]))(
    "reproduces the published intermediates for %s",
    (_name, v: any) => {
      const bip39 = recovery.toSeed(v.phrase, v.passphrase);
      expect(hex(bip39)).toBe(v.bip39Seed);
      expect(hex(recovery.deriveSeed(v.type as KeyType, bip39))).toBe(v.derivedSeed);
    }
  );

  it("agrees with restoreBIP39Key", async () => {
    for (const type of [KeyType.EllipticCurve, KeyType.MLDSA65, KeyType.Falcon512]) {
      const phrase = phraseVectors[0].phrase;

      const viaHandler = await handler.restoreBIP39Key("k", phrase, { type, compressed: true });
      const viaModule = await handler.generateKeyFromSeed(
        "k",
        recovery.deriveSeed(type, recovery.toSeed(phrase)),
        true,
        type
      );

      expect(viaModule.key.pub.pkcs8pem).toBe(viaHandler.key.pub.pkcs8pem);
    }
  });

  it("validates by default, naming what is wrong", () => {
    expect(() => recovery.toSeed("abandon ".repeat(11) + "abandon")).toThrow(/checksum/);
    expect(() => recovery.toSeed("abandon ".repeat(11) + "zzzz")).toThrow(/zzzz/);
    expect(() => recovery.toSeed("abandon abandon abandon")).toThrow(/12, 15, 18, 21 or 24/);
  });

  it("can skip validation, within what @scure allows", () => {
    // 12 words that are not in the wordlist: @scure accepts the shape and
    // derives from it, which is what restoreBIP39Key has always done here.
    expect(recovery.toSeed("zzzz ".repeat(11) + "zzzz", "", { validate: false })).toHaveLength(64);
  });

  it("restoreBIP39Key validates here too, identically to sdk-node", async () => {
    await expect(
      handler.restoreBIP39Key("k", "abandon ".repeat(11) + "abandon")
    ).rejects.toThrow(/checksum/);
    await expect(
      handler.restoreBIP39Key("k", "zzzz ".repeat(11) + "zzzz", { validate: false })
    ).resolves.toBeDefined();
  });

  it("skipping validation accepts any string, exactly as sdk-node does", async () => {
    // @scure/bip39 enforces the word count inside mnemonicToSeedSync, so the
    // unchecked seed is computed here with PBKDF2 directly. The expected keys
    // were produced by sdk-node's restoreBIP39Key({ validate: false }) for the
    // same inputs - the same phrase must be the same identity on both.
    const phrase = "not a real mnemonic at all";

    expect(() => recovery.toSeed(phrase)).toThrow();
    expect(recovery.toSeed(phrase, "", { validate: false })).toHaveLength(64);

    const plain = await handler.restoreBIP39Key("k", phrase, { validate: false, compressed: true });
    expect(plain.key.prv.pkcs8pem).toBe("0x739c20553484a4d919364a20181ca4f79cb9944fe77719736151825d29b37174");
    expect(plain.key.pub.pkcs8pem).toBe("0x02d3d4b93a1d3d62f339d47ffbce11d8c660e9d2a8f85208215273f9eb38b29a22");

    // The passphrase is NFKD-normalised into the salt.
    const salted = await handler.restoreBIP39Key("k", phrase, {
      validate: false,
      compressed: true,
      passphrase: "p\u00e4ssword",
    });
    expect(salted.key.prv.pkcs8pem).toBe("0xd8082d6d3a25a8841539d7dddcef2ec98886231e709a1e91b949549e2fd0cc25");
    expect(salted.key.pub.pkcs8pem).toBe("0x03c1f87797ad13e6762f1750a1f729fc8059063a4e50716b6d2a9e92ad17486c1c");
  });

  it("the unchecked seed equals the validated seed for a valid phrase", () => {
    for (const v of phraseVectors.filter((x) => x.scheme === "v1")) {
      expect(hex(recovery.unvalidatedSeed(v.phrase, v.passphrase))).toBe(v.bip39Seed);
    }
  });

  it("refuses a BIP-39 seed of the wrong length", () => {
    expect(() => recovery.deriveSeed(KeyType.MLDSA65, new Uint8Array(32))).toThrow(/64 bytes/);
  });

  it("exposes the secp256k1 master-key step", () => {
    const bip39 = recovery.toSeed(phraseVectors[0].phrase);

    expect(hex(recovery.deriveBIP32MasterKey(bip39))).toBe(
      hex(recovery.deriveSeed(KeyType.EllipticCurve, bip39))
    );
  });
});
