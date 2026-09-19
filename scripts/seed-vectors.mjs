// Generates the cross-language SEED and RECOVERY-PHRASE vectors.
//
// Separate from pq-vectors.json deliberately. That file publishes signatures
// six SDK repositories check themselves against, and regenerating it reissues
// every one of them. Nothing here signs anything, so the two have no reason
// to share a generation run.
//
// Regenerate with: npm run vectors:seed
//
// There are TWO layers here and conflating them is the mistake this file is
// arranged to prevent.
//
//   fromSeed(type, seed)   takes the ALGORITHM'S OWN seed. No derivation, no
//                          KDF, no phrase. 32 bytes for ml-dsa-65 and
//                          secp256k1, 48 for falcon-512. This is the portable
//                          private-key format: the same seed gives the same
//                          identity in every SDK.
//
//   fromPhrase(type, ...)  takes a BIP-39 recovery phrase, derives a seed for
//                          the requested type, and hands it to fromSeed.
//
// Layer one is what makes PHP interoperable at all. paragonie/pqcrypto_compat
// implements FIPS 204 keygen from a seed but not skEncode/skDecode, so an
// ml-dsa-65 private key there IS a 32-byte seed and the 4032-byte encoding
// every other SDK exports cannot be loaded. Once every SDK can import a seed,
// that stops being a dead end.

import { createRequire } from "module";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const { ml_dsa65 } = require("@noble/post-quantum/ml-dsa.js");
const { falcon512 } = require("@noble/post-quantum/falcon.js");
const { mnemonicToSeedSync } = require("bip39");

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, "..", "vectors", "seed-vectors.json");

// secp256k1's group order. A scalar must be in [1, n-1]; 0 and anything at or
// above n is not a private key, and a library handed one either throws or -
// worse - reduces it silently into a different identity.
const N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

const hex = (b) => Buffer.from(b).toString("hex");
const b64 = (b) => Buffer.from(b).toString("base64");

// ---------------------------------------------------------------------------
// The derivation, in one place. Everything below calls these.
// ---------------------------------------------------------------------------

const SEED_SIZES = { "ml-dsa-65": 32, "falcon-512": 48, secp256k1: 32 };

// The info string carries a version so a future scheme is distinguishable
// rather than silently incompatible. salt is empty, which HKDF defines as a
// block of zero bytes of the hash length - checked identical between node's
// crypto.hkdfSync, PHP's hash_hkdf and a hand-rolled HMAC loop.
const INFO = (type) => `activeledger-seed-v1:${type}`;

function hkdf(bip39Seed, type, length) {
  return Buffer.from(
    crypto.hkdfSync("sha512", bip39Seed, Buffer.alloc(0), Buffer.from(INFO(type), "utf8"), length),
  );
}

// secp256k1 is NOT HKDF-derived, and that is not an oversight.
//
// @activeledger/sdk-node and sdk-web have shipped restoreBIP39Key with this
// exact derivation, so phrases already exist in the wild. Changing it would
// silently hand those users a different key for a phrase that used to work -
// the identity would simply not be theirs any more, with no error anywhere.
// The post-quantum types are new and carry no such debt, so they get the
// cleaner construction.
function secp256k1FromPhraseSeed(bip39Seed) {
  return crypto.createHmac("sha512", "Bitcoin seed").update(bip39Seed).digest().subarray(0, 32);
}

function deriveSeed(type, bip39Seed) {
  return type === "secp256k1"
    ? secp256k1FromPhraseSeed(bip39Seed)
    : hkdf(bip39Seed, type, SEED_SIZES[type]);
}

// ---------------------------------------------------------------------------
// Key generation from a seed, per type, in each SDK's own published encoding.
// ---------------------------------------------------------------------------

function keysFromSeed(type, seed, compressed = true) {
  if (seed.length !== SEED_SIZES[type]) {
    throw new Error(`${type} seed must be ${SEED_SIZES[type]} bytes, got ${seed.length}`);
  }

  if (type === "secp256k1") {
    // The seed IS the scalar. Rejected rather than reduced: a scalar outside
    // the group is not this identity, and a library that quietly reduces it
    // produces a working key that is the wrong one.
    const scalar = BigInt("0x" + hex(seed));
    if (scalar === 0n || scalar >= N) return null;

    const curve = crypto.createECDH("secp256k1");
    curve.setPrivateKey(seed);
    return {
      publicKey: "0x" + curve.getPublicKey("hex", compressed ? "compressed" : "uncompressed"),
      // seed, not curve.getPrivateKey() - that strips leading zero bytes.
      privateKey: "0x" + hex(seed),
    };
  }

  const scheme = type === "ml-dsa-65" ? ml_dsa65 : falcon512;
  const kp = scheme.keygen(seed);
  return { publicKey: b64(kp.publicKey), privateKey: b64(kp.secretKey) };
}

// ---------------------------------------------------------------------------
// Cases.
// ---------------------------------------------------------------------------

const TYPES = ["ml-dsa-65", "falcon-512", "secp256k1"];

// Chosen for the edges, not for variety. `valid: false` cases are published
// because a port that reduces a bad scalar instead of refusing it produces a
// working key belonging to someone else, and nothing downstream notices.
const SEED_CASES = [
  {
    name: "zeros",
    // Perfectly good post-quantum seed. NOT a secp256k1 scalar - zero is not
    // a private key, and a library that accepts it is wrong.
    bytes: (n) => Buffer.alloc(n, 0x00),
  },
  {
    name: "ones",
    // 0xff repeated is above the secp256k1 group order. Reducing it mod n
    // gives a valid-looking key that is not the one the seed names.
    bytes: (n) => Buffer.alloc(n, 0xff),
  },
  {
    name: "leading-zero",
    // Starts 0x00. For secp256k1 this is the left-padding case: a port that
    // round-trips through a bignum drops the byte and exports 62 hex
    // characters, which strict readers reject and lenient ones misread.
    bytes: (n) => Buffer.concat([Buffer.alloc(1, 0x00), Buffer.alloc(n - 1, 0x2a)]),
  },
  {
    name: "counter",
    bytes: (n) => Buffer.from(Array.from({ length: n }, (_, i) => i & 0xff)),
  },
  {
    name: "fixed-random",
    // Stable across regenerations - derived from the case name, not from an
    // RNG, so this file does not churn.
    bytes: (n) => crypto.createHash("sha512").update("activeledger-seed-vectors").digest().subarray(0, n),
  },
];

// The standard BIP-39 test phrases, plus a passphrase case. The passphrase is
// part of the seed derivation, so the same phrase with and without one must
// give entirely different identities - a port that ignores the argument
// passes every other test here.
const PHRASE_CASES = [
  {
    name: "abandon",
    phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    passphrase: "",
  },
  {
    name: "legal-winner",
    phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow",
    passphrase: "",
  },
  { name: "zoo", phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", passphrase: "" },
  {
    name: "abandon-passphrase",
    phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    passphrase: "TREZOR",
  },
];

const EC_FORMS = [
  { form: "compressed", compressed: true },
  { form: "uncompressed", compressed: false },
];

const seedVectors = [];
for (const type of TYPES) {
  const size = SEED_SIZES[type];

  for (const kase of SEED_CASES) {
    const seed = kase.bytes(size);
    const forms = type === "secp256k1" ? EC_FORMS : [{ form: null, compressed: true }];

    for (const { form, compressed } of forms) {
      const keys = keysFromSeed(type, seed, compressed);
      const vector = { type, seedName: kase.name, seedSize: size, seed: hex(seed) };
      if (form) vector.publicKeyForm = form;

      if (keys === null) {
        vector.valid = false;
        vector.reason =
          "not a secp256k1 scalar - must be in [1, n-1]. Refuse it; do not reduce it mod n.";
      } else {
        vector.valid = true;
        Object.assign(vector, keys);
      }

      seedVectors.push(vector);
      if (!keys) break; // one rejection vector is enough; it is not form-specific
    }
  }
}

const phraseVectors = [];
for (const kase of PHRASE_CASES) {
  const bip39Seed = mnemonicToSeedSync(kase.phrase, kase.passphrase);

  for (const type of TYPES) {
    const derived = deriveSeed(type, bip39Seed);
    const forms = type === "secp256k1" ? EC_FORMS : [{ form: null, compressed: true }];

    for (const { form, compressed } of forms) {
      const keys = keysFromSeed(type, derived, compressed);
      if (!keys) throw new Error(`phrase ${kase.name}/${type} derived an unusable seed`);

      const vector = {
        type,
        phraseName: kase.name,
        phrase: kase.phrase,
        passphrase: kase.passphrase,
        bip39Seed: hex(bip39Seed),
        derivedSeed: hex(derived),
        scheme: "v1",
      };
      if (form) vector.publicKeyForm = form;
      Object.assign(vector, keys);
      phraseVectors.push(vector);
    }
  }

  // The pre-existing scheme, secp256k1 only: SHA256(phrase) used directly as
  // the scalar, no KDF and no passphrase. Published so a port CAN recover a
  // phrase made by @activeledger/sdk-bip39, never so it can make new ones.
  if (!kase.passphrase) {
    const legacyScalar = crypto.createHash("sha256").update(kase.phrase, "utf8").digest();
    for (const { form, compressed } of EC_FORMS) {
      const keys = keysFromSeed("secp256k1", legacyScalar, compressed);
      if (!keys) continue;
      phraseVectors.push({
        type: "secp256k1",
        phraseName: kase.name,
        phrase: kase.phrase,
        passphrase: "",
        bip39Seed: hex(bip39Seed),
        derivedSeed: hex(legacyScalar),
        scheme: "legacy",
        publicKeyForm: form,
        ...keys,
      });
    }
  }
}

// ---------------------------------------------------------------------------

const HEADER = [
  "Seed and recovery-phrase vectors for Activeledger SDKs.",
  "",
  "Generated by scripts/seed-vectors.mjs from the JavaScript SDK, which is",
  "the reference implementation. Do not hand-edit.",
  "",
  "Signatures live in pq-vectors.json. Nothing here signs anything: these",
  "cover key DERIVATION only, and the two files are regenerated separately.",
  "",
  "TWO LAYERS, AND THEY ARE NOT THE SAME THING.",
  "",
  "  fromSeed(type, seed) takes the ALGORITHM'S OWN seed - no KDF, no phrase.",
  "  `seedVectors` covers it. This is the portable private-key format: the",
  "  same bytes give the same identity in every SDK and every library. Seed",
  "  sizes are 32 bytes for ml-dsa-65, 48 for falcon-512, 32 for secp256k1,",
  "  and they are fixed - a library handed the wrong length must refuse it,",
  "  not pad or truncate.",
  "",
  "  fromPhrase(type, phrase, passphrase) derives that seed from a BIP-39",
  "  recovery phrase. `phraseVectors` covers it, and publishes the",
  "  intermediate `bip39Seed` and `derivedSeed` so a port can tell WHICH step",
  "  it got wrong rather than only that the final key differs.",
  "",
  "WHY SEEDS MATTER BEYOND RECOVERY. An ml-dsa-65 private key in the PHP SDK",
  "IS a 32-byte seed: paragonie/pqcrypto_compat implements FIPS 204 key",
  "generation from a seed but not skEncode/skDecode, so the 4032-byte",
  "encoding every other SDK exports cannot be loaded there at all. A seed is",
  "the one private-key form all seven can agree on. Verified: the same 32",
  "bytes produce an identical 1952-byte public key in PHP and in JavaScript.",
  "",
  "THE DERIVATION, in full, so a port never has to infer it:",
  "",
  "  BIP-39 seed S = PBKDF2-HMAC-SHA512(phrase, \"mnemonic\" + passphrase,",
  "                                     2048 iterations, 64 bytes)",
  "",
  "  ml-dsa-65   seed = HKDF-SHA512(ikm = S, salt = \"\",",
  "                                 info = \"activeledger-seed-v1:ml-dsa-65\",",
  "                                 L = 32)",
  "",
  "  falcon-512  seed = HKDF-SHA512(ikm = S, salt = \"\",",
  "                                 info = \"activeledger-seed-v1:falcon-512\",",
  "                                 L = 48)",
  "",
  "  secp256k1   scalar = HMAC-SHA512(key = \"Bitcoin seed\", msg = S)[0..32]",
  "",
  "An empty HKDF salt means a block of zero bytes of the hash length, which",
  "is what RFC 5869 specifies and what node's crypto.hkdfSync, PHP's",
  "hash_hkdf and a hand-rolled HMAC loop all do - checked byte for byte, as",
  "it is the detail most likely to differ quietly between implementations.",
  "",
  "SECP256K1 DOES NOT USE HKDF, AND THAT IS DELIBERATE. @activeledger/sdk-node",
  "and sdk-web have shipped restoreBIP39Key with the BIP-32 master-key step",
  "above since before this file existed, so phrases already exist. Moving it",
  "onto HKDF would hand every one of those users a different key for a phrase",
  "that used to work - not an error, just an identity that is no longer",
  "theirs. The post-quantum types are new and carry no such debt, so they get",
  "the construction with proper domain separation. The two schemes share a",
  "BIP-39 seed but no derivation path, so one type's key never reveals",
  "another's.",
  "",
  "`scheme` ON PHRASE VECTORS. \"v1\" is everything above. \"legacy\" is the",
  "original @activeledger/sdk-bip39 scheme - SHA256(phrase) used directly as",
  "the scalar, no KDF, no domain separation, no passphrase - and it appears",
  "for secp256k1 only. Implement it to RECOVER a phrase made by that package.",
  "Never generate with it.",
  "",
  "INVALID SEEDS ARE PUBLISHED TOO. `valid: false` marks a seed that is not a",
  "usable secp256k1 scalar, which must be in [1, n-1]. Refuse it. A library",
  "that reduces it mod n instead returns a perfectly functional key for a",
  "different identity, and nothing downstream ever reports a problem. The",
  "post-quantum schemes have no such constraint: every byte string of the",
  "right length is a seed.",
  "",
  "ENCODINGS match pq-vectors.json exactly. Post-quantum keys are base64 of",
  "the raw bytes; secp256k1 keys are 0x-prefixed hex, with `publicKeyForm`",
  "saying whether the public key is compressed (33 bytes) or uncompressed",
  "(65). `seed` and `derivedSeed` are plain hex with NO 0x prefix for every",
  "type, because a seed is bytes rather than a ledger-facing key.",
  "",
  "Private keys are LEFT-PADDED to their full length. The `leading-zero` case",
  "exists for that: a port that round-trips a secp256k1 scalar through a",
  "bignum drops the leading byte and exports 62 hex characters instead of 64.",
];

const doc = {
  header: HEADER.join("\n"),
  generated: new Date().toISOString(),
  derivation: {
    bip39: "PBKDF2-HMAC-SHA512(phrase, 'mnemonic' + passphrase, 2048, 64)",
    "ml-dsa-65": "HKDF-SHA512(S, salt='', info='activeledger-seed-v1:ml-dsa-65', 32)",
    "falcon-512": "HKDF-SHA512(S, salt='', info='activeledger-seed-v1:falcon-512', 48)",
    secp256k1: "HMAC-SHA512('Bitcoin seed', S)[0..32]",
    legacy: "SHA256(phrase) - secp256k1 recovery only, never for new keys",
  },
  seedSizes: SEED_SIZES,
  seedVectors,
  phraseVectors,
};

fs.writeFileSync(OUT, JSON.stringify(doc, null, 2) + "\n");

console.log(`wrote ${path.relative(process.cwd(), OUT)}`);
console.log(`  seedVectors   ${seedVectors.length} (${seedVectors.filter((v) => !v.valid).length} invalid)`);
console.log(`  phraseVectors ${phraseVectors.length}`);
