import * as fs from "fs";
import * as path from "path";
import { KeyType } from "@activeledger/sdk-core";
import * as recovery from "../recovery";
import { KeyHandler } from "../key";

/**
 * The public recovery module.
 *
 * It exists because this was the only SDK of the seven where a caller could
 * not reach the derivation without reimplementing it - which is how a second,
 * drifting copy of a KDF gets written.
 */
describe("recovery (sdk-node)", () => {
  const handler = new KeyHandler();
  const vectors = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../../../../vectors/seed-vectors.json"), "utf8")
  );
  const phraseVectors: any[] = vectors.phraseVectors;

  it.each(phraseVectors.filter((v) => v.scheme === "v1").map((v) => [`${v.type}/${v.phraseName}`, v]))(
    "reproduces the published intermediates for %s",
    (_name, v: any) => {
      const bip39 = recovery.toSeed(v.phrase, v.passphrase);
      expect(bip39.toString("hex")).toBe(v.bip39Seed);
      expect(recovery.deriveSeed(v.type as KeyType, bip39).toString("hex")).toBe(v.derivedSeed);
    }
  );

  it("agrees with restoreBIP39Key, which is the point of exposing it", async () => {
    // If these ever diverge there are two derivations in one package, which is
    // the exact failure this module was added to prevent elsewhere.
    for (const type of [KeyType.EllipticCurve, KeyType.MLDSA65, KeyType.Falcon512]) {
      const phrase = phraseVectors[0].phrase;

      // compressed passed on BOTH sides - restoreBIP39Key defaults to
      // uncompressed, which is the same key in a different point encoding.
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

  it("derives a falcon-512 seed even where Falcon is unavailable elsewhere", () => {
    // The reason the module is useful on its own: the seed is portable even
    // when the scheme is not implemented in the SDK that needs it.
    const seed = recovery.deriveSeed(KeyType.Falcon512, recovery.toSeed(phraseVectors[0].phrase));
    expect(seed).toHaveLength(48);
  });

  it("gives each key type its own seed", () => {
    const bip39 = recovery.toSeed(phraseVectors[0].phrase);
    const seeds = [KeyType.EllipticCurve, KeyType.MLDSA65, KeyType.Falcon512].map((t) =>
      recovery.deriveSeed(t, bip39).toString("hex")
    );

    expect(new Set(seeds).size).toBe(3);
  });

  it("validates by default, naming what is wrong", () => {
    expect(() => recovery.toSeed("abandon ".repeat(11) + "abandon")).toThrow(/checksum/);
    expect(() => recovery.toSeed("abandon ".repeat(11) + "zzzz")).toThrow(/zzzz/);
    expect(() => recovery.toSeed("abandon abandon abandon")).toThrow(/12, 15, 18, 21 or 24/);
  });

  it("can skip validation, because restoreBIP39Key always has", () => {
    // Neither bip39 nor @scure/bip39 validates inside mnemonicToSeedSync, so
    // this SDK has always accepted an arbitrary string. Someone may rely on
    // it, and rejecting their phrase now would orphan an identity.
    const lenient = recovery.toSeed("not a real mnemonic at all", "", { validate: false });
    expect(lenient).toHaveLength(64);
  });

  it("restoreBIP39Key now validates, and says how to opt out", async () => {
    // Was lenient before 2.4.0. A typo derived a different VALID key for an
    // identity nobody owns, and only the ledger ever noticed.
    await expect(
      handler.restoreBIP39Key("k", "abandon ".repeat(11) + "abandon")
    ).rejects.toThrow(/checksum.*\{ validate: false \}/s);

    await expect(handler.restoreBIP39Key("k", "not a real mnemonic at all")).rejects.toThrow(
      /12, 15, 18, 21 or 24/
    );
  });

  it("the opt-out restores the pre-2.4.0 behaviour", async () => {
    // Kept because someone may have used an arbitrary string deliberately.
    // Refusing it now would make that identity unrecoverable, which is the
    // same failure validation exists to prevent, pointed the other way.
    await expect(
      handler.restoreBIP39Key("k", "not a real mnemonic at all", { validate: false })
    ).resolves.toBeDefined();
  });

  it("the legacy scheme is never validated", async () => {
    // SHA256 of the string, never a BIP-39 mnemonic operation. The original
    // sdk-bip39 package never consulted the wordlist, so refusing a phrase it
    // accepted would orphan a recoverable identity.
    await expect(
      handler.restoreBIP39Key("k", "not a real mnemonic at all", { legacy: true })
    ).resolves.toBeDefined();
  });

  it("validation makes both platforms agree, which they did not before", async () => {
    // @scure/bip39 enforces the word count inside mnemonicToSeedSync; node's
    // bip39 enforces nothing. With validation on by default the difference is
    // no longer reachable through restoreBIP39Key.
    expect(() => recovery.toSeed("not a real mnemonic at all")).toThrow(/12, 15, 18, 21 or 24/);
  });

  it("refuses a BIP-39 seed of the wrong length", () => {
    expect(() => recovery.deriveSeed(KeyType.MLDSA65, new Uint8Array(32))).toThrow(/64 bytes/);
  });

  it("reports a key type that has no seed derivation", () => {
    expect(() => recovery.seedSize("rsa" as KeyType)).toThrow(/cannot be derived from a seed/);
  });

  it("an empty HKDF salt and an omitted one give the same seed", () => {
    // Worth pinning: it reads as a discrepancy against the other SDKs, which
    // pass salt="". HMAC pads a short key to the block size, and a zero-length
    // key pads to the same all-zero block RFC 5869 specifies.
    const crypto = require("crypto");
    const bip39 = recovery.toSeed(phraseVectors[0].phrase);
    const info = Buffer.from(`activeledger-seed-v1:${KeyType.MLDSA65}`, "utf8");

    const omitted = Buffer.from(crypto.hkdfSync("sha512", bip39, Buffer.alloc(0), info, 32));
    expect(recovery.deriveSeed(KeyType.MLDSA65, bip39).equals(omitted)).toBe(true);
  });

  it("exposes the secp256k1 master-key step, which differs from a BIP-32 child", () => {
    // Varnir's client derives a child at m/44'/1'/0'/0/0 from the same phrase
    // and gets a different identity. Exposed so that is checkable rather than
    // inferred.
    const bip39 = recovery.toSeed(phraseVectors[0].phrase);

    expect(recovery.deriveBIP32MasterKey(bip39)).toHaveLength(32);
    expect(recovery.deriveBIP32MasterKey(bip39).toString("hex")).toBe(
      recovery.deriveSeed(KeyType.EllipticCurve, bip39).toString("hex")
    );
  });
});
