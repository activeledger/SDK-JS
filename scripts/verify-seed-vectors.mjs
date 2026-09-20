// Checks the committed seed/phrase vector file against this SDK.
//
// Runs in npm test, for the same reason verify-vectors.mjs does: the
// generator validates as it writes, but nothing would catch a file that was
// edited, truncated, merged badly, or generated from a broken build and then
// committed. Six other SDK repositories treat it as the definition of
// correct.
//
// It also guards the change that would be silent and unrecoverable: a phrase
// derivation that drifts. Phrases are already in use for every key type, so
// every vector is checked against the LIVE recovery.deriveSeed and the live
// restoreBIP39Key rather than against a second copy of the formula. A change
// to any derivation fails the build rather than quietly reassigning someone's
// identity.

import { createRequire } from "module";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const { ml_dsa65 } = require("@noble/post-quantum/ml-dsa.js");
const { falcon512 } = require("@noble/post-quantum/falcon.js");
const { mnemonicToSeedSync } = require("bip39");
const { KeyHandler, recovery } = require("../packages/node/lib/index.js");

const here = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = path.join(here, "..", "vectors", "seed-vectors.json");

if (!fs.existsSync(VECTORS)) {
  console.error(`No seed vector file at ${VECTORS} - run 'npm run vectors:seed'`);
  process.exit(1);
}

const doc = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
let failures = 0;
const check = (condition, message) => {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    failures++;
  }
};

const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SIZES = { "ml-dsa-65": 32, "falcon-512": 48, secp256k1: 32 };
const raw = (s) => Buffer.from(s, "base64");

// --- structure ------------------------------------------------------------

check(Array.isArray(doc.seedVectors) && doc.seedVectors.length > 0, "seedVectors missing or empty");
check(Array.isArray(doc.phraseVectors) && doc.phraseVectors.length > 0, "phraseVectors missing or empty");
check(typeof doc.header === "string" && doc.header.includes("activeledger-seed-v1"), "header must state the derivation");

for (const [type, size] of Object.entries(SIZES)) {
  check(doc.seedSizes?.[type] === size, `seedSizes.${type} should be ${size}, got ${doc.seedSizes?.[type]}`);
}

// A regeneration that dropped a type would otherwise pass everything below.
for (const type of Object.keys(SIZES)) {
  check(doc.seedVectors.some((v) => v.type === type), `no seedVectors for ${type}`);
  check(doc.phraseVectors.some((v) => v.type === type), `no phraseVectors for ${type}`);
}

// The invalid-scalar cases are the point of the secp256k1 section. Without
// them a port can accept a zero scalar and still pass.
check(
  doc.seedVectors.filter((v) => v.valid === false).length >= 2,
  "expected at least two invalid secp256k1 seed vectors",
);

// --- fromSeed -------------------------------------------------------------

function derive(type, seed, compressed) {
  if (type === "secp256k1") {
    const scalar = BigInt("0x" + seed.toString("hex"));
    if (scalar === 0n || scalar >= N) return null;
    const curve = crypto.createECDH("secp256k1");
    curve.setPrivateKey(seed);
    return {
      publicKey: "0x" + curve.getPublicKey("hex", compressed ? "compressed" : "uncompressed"),
      privateKey: "0x" + seed.toString("hex"),
    };
  }
  const kp = (type === "ml-dsa-65" ? ml_dsa65 : falcon512).keygen(seed);
  return {
    publicKey: Buffer.from(kp.publicKey).toString("base64"),
    privateKey: Buffer.from(kp.secretKey).toString("base64"),
  };
}

for (const v of doc.seedVectors) {
  const where = `seedVectors ${v.type}/${v.seedName}${v.publicKeyForm ? "/" + v.publicKeyForm : ""}`;
  const seed = Buffer.from(v.seed, "hex");

  check(!v.seed.startsWith("0x"), `${where}: seed must be bare hex, not 0x-prefixed`);
  check(seed.length === SIZES[v.type], `${where}: seed is ${seed.length} bytes, expected ${SIZES[v.type]}`);
  check(v.seedSize === SIZES[v.type], `${where}: seedSize field disagrees with the type`);

  const got = derive(v.type, seed, v.publicKeyForm !== "uncompressed");

  if (v.valid === false) {
    check(v.type === "secp256k1", `${where}: only secp256k1 seeds can be invalid`);
    check(got === null, `${where}: marked invalid but derives a key`);
    check(typeof v.reason === "string" && v.reason.length > 0, `${where}: invalid vectors need a reason`);
    check(v.publicKey === undefined, `${where}: invalid vectors must not carry a key`);
    continue;
  }

  check(got !== null, `${where}: marked valid but does not derive`);
  if (!got) continue;
  check(got.publicKey === v.publicKey, `${where}: public key differs from this SDK`);
  check(got.privateKey === v.privateKey, `${where}: private key differs from this SDK`);

  if (v.type === "secp256k1") {
    check(v.privateKey.length === 66, `${where}: private key must be left-padded to 66 chars, got ${v.privateKey.length}`);
    check(v.publicKey.length === (v.publicKeyForm === "compressed" ? 68 : 132), `${where}: wrong public key length`);
  } else {
    const [pub, prv] = v.type === "ml-dsa-65" ? [1952, 4032] : [897, 1281];
    check(raw(v.publicKey).length === pub, `${where}: public key should be ${pub} bytes`);
    check(raw(v.privateKey).length === prv, `${where}: private key should be ${prv} bytes`);
  }
}

// A seed that starts 0x00 is the one that catches a port stripping leading
// zero bytes, so the file must actually contain one.
check(
  doc.seedVectors.some((v) => v.valid && v.type === "secp256k1" && v.privateKey.startsWith("0x00")),
  "no secp256k1 vector with a leading zero byte - the left-padding case is untested",
);

// --- fromPhrase -----------------------------------------------------------

const hkdf = (s, type, len) =>
  Buffer.from(crypto.hkdfSync("sha512", s, Buffer.alloc(0), Buffer.from(`activeledger-seed-v1:${type}`, "utf8"), len));

const kh = new KeyHandler();
let shippedChecked = 0;

for (const v of doc.phraseVectors) {
  const where = `phraseVectors ${v.type}/${v.phraseName}/${v.scheme}${v.publicKeyForm ? "/" + v.publicKeyForm : ""}`;
  const bip39Seed = mnemonicToSeedSync(v.phrase, v.passphrase || "");

  check(bip39Seed.toString("hex") === v.bip39Seed, `${where}: bip39Seed does not match PBKDF2 of the phrase`);

  let expectedSeed;
  if (v.scheme === "legacy") {
    check(v.type === "secp256k1", `${where}: legacy applies to secp256k1 only`);
    check(v.passphrase === "", `${where}: the legacy scheme has no passphrase`);
    expectedSeed = crypto.createHash("sha256").update(v.phrase, "utf8").digest();
  } else if (v.type === "secp256k1") {
    expectedSeed = crypto.createHmac("sha512", "Bitcoin seed").update(bip39Seed).digest().subarray(0, 32);
  } else {
    expectedSeed = hkdf(bip39Seed, v.type, SIZES[v.type]);
  }

  check(expectedSeed.toString("hex") === v.derivedSeed, `${where}: derivedSeed does not match the published derivation`);

  const got = derive(v.type, Buffer.from(v.derivedSeed, "hex"), v.publicKeyForm !== "uncompressed");
  check(got?.publicKey === v.publicKey, `${where}: public key differs from this SDK`);
  check(got?.privateKey === v.privateKey, `${where}: private key differs from this SDK`);
}

// The SDK'S OWN derivation, not a second copy of the formula.
//
// Everything above recomputes HKDF inline and calls noble directly, which
// checks the FILE but not the implementation - so changing recovery.deriveSeed
// left this script green. Found by breaking the post-quantum info string on
// purpose and watching it pass. The jest suite caught it, but this script is
// the one the other six SDKs are modelled on, and it had the asymmetry it
// exists to prevent: secp256k1 pinned to live code, the post-quantum pair not.
for (const v of doc.phraseVectors.filter((x) => x.scheme === "v1")) {
  const where = `phraseVectors ${v.type}/${v.phraseName}`;
  const bip39 = recovery.toSeed(v.phrase, v.passphrase || "", { validate: false });

  check(
    Buffer.from(bip39).toString("hex") === v.bip39Seed,
    `${where}: the SDK's recovery.toSeed no longer reproduces this BIP-39 seed`,
  );
  check(
    Buffer.from(recovery.deriveSeed(v.type, bip39)).toString("hex") === v.derivedSeed,
    `${where}: DERIVATION CHANGED - the SDK's recovery.deriveSeed no longer reproduces ` +
      "this seed, so every existing phrase now resolves to a different identity",
  );
}

// Phrases generated by the shipped restoreBIP39Key must keep resolving to the
// same identity, for every type rather than only the one with prior art.
await Promise.all(
  doc.phraseVectors
    .filter((v) => v.type === "secp256k1" || v.scheme === "v1")
    .map(async (v) => {
      const k = await kh.restoreBIP39Key("k", v.phrase, {
        compressed: v.publicKeyForm === "compressed",
        passphrase: v.passphrase || undefined,
        legacy: v.scheme === "legacy",
        type: v.type,
      });
      shippedChecked++;
      check(
        k.key.pub.pkcs8pem === v.publicKey && k.key.prv.pkcs8pem === v.privateKey,
        `phraseVectors ${v.phraseName}/${v.scheme}/${v.publicKeyForm}: DERIVATION CHANGED - ` +
          "the shipped restoreBIP39Key no longer reproduces this vector, so every existing phrase now " +
          "resolves to a different identity",
      );
    }),
);

// Domain separation, checked rather than asserted in prose: no two types may
// derive the same seed from one phrase.
for (const name of new Set(doc.phraseVectors.map((v) => v.phraseName))) {
  const seeds = doc.phraseVectors
    .filter((v) => v.phraseName === name && v.scheme === "v1")
    .map((v) => `${v.type}:${v.derivedSeed}`);
  const bare = [...new Set(seeds.map((s) => s.split(":")[1]))];
  check(bare.length === new Set(doc.phraseVectors.filter((v) => v.phraseName === name && v.scheme === "v1").map((v) => v.type)).size,
    `phrase ${name}: two key types derive the same seed - domain separation is broken`);
}

// A passphrase must change the identity, or the argument is being dropped.
const plain = doc.phraseVectors.find((v) => v.phraseName === "abandon" && v.type === "ml-dsa-65");
const withPass = doc.phraseVectors.find((v) => v.phraseName === "abandon-passphrase" && v.type === "ml-dsa-65");
check(plain && withPass, "the passphrase comparison vectors are missing");
if (plain && withPass) {
  check(plain.publicKey !== withPass.publicKey, "the same phrase with a passphrase derives the same key - the passphrase is ignored");
}

if (failures) {
  console.error(`\n${failures} seed vector check(s) failed`);
  process.exit(1);
}

console.log(
  `seed vectors OK - ${doc.seedVectors.length} seed, ${doc.phraseVectors.length} phrase ` +
    `(${shippedChecked} checked against the shipped restoreBIP39Key)`,
);
