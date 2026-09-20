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

  it("skipping validation is NOT the same leniency as sdk-node", () => {
    // A pre-existing platform difference, pinned rather than papered over.
    // @scure/bip39 enforces the word count inside mnemonicToSeedSync; node's
    // bip39 enforces nothing. So restoreBIP39Key("arbitrary string") derives a
    // key on sdk-node and throws here. Neither side can be changed safely:
    // relaxing web is harmless but pointless, and tightening node would reject
    // phrases that currently work and orphan whatever they unlock.
    //
    // This is exactly why toSeed validates BY DEFAULT - it is the only way to
    // get the same answer on both platforms.
    expect(() => recovery.toSeed("not a real mnemonic at all", "", { validate: false })).toThrow();
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
