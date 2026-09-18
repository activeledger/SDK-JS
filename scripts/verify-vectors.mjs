// Checks the committed cross-language vector file against this SDK.
//
// Runs in npm test. Its job is to stop a bad regeneration shipping silently:
// scripts/pq-vectors.mjs validates as it writes, but nothing would catch a
// vectors file that was edited, truncated, merged badly, or generated from a
// broken build and then committed. Every non-JS SDK trusts this file as the
// definition of correct, so it has to be checked on every run, not on the day
// it was written.

import { createRequire } from "module";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const require = createRequire(import.meta.url);
const { NodeCryptoProvider } = require("../packages/node/lib/index.js");
const provider = new NodeCryptoProvider();

const here = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = path.join(here, "..", "vectors", "pq-vectors.json");

if (!fs.existsSync(VECTORS)) {
  console.error(`No vector file at ${VECTORS} - run 'npm run vectors'`);
  process.exit(1);
}

const doc = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
const vectors = doc.vectors || [];

let failures = 0;
function check(condition, message) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    failures++;
  }
}

const b64len = (s) => Buffer.from(s, "base64").length;

// secp256k1's group order, and the halfway point that divides "low S" from
// "high S".
const SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const SECP256K1_HALF_N = SECP256K1_N / 2n;

/**
 * Pulls S out of a DER ECDSA signature.
 *
 * Only needed to tell high-S signatures from low-S ones, which matters more
 * than it sounds: several libraries REJECT high-S by default (@noble/curves
 * and libsecp256k1 among them), while the ledger verifies through OpenSSL,
 * which neither normalises nor requires it. A port that inherits its
 * library's default silently rejects about half of all valid ledger
 * signatures - an intermittent failure that looks like anything but a
 * configuration flag.
 */
function derSignatureS(der) {
  let i = 2;
  if (der[i] !== 0x02) throw new Error("malformed DER: expected R");
  i += 2 + der[i + 1];
  if (der[i] !== 0x02) throw new Error("malformed DER: expected S");
  const s = der.subarray(i + 2, i + 2 + der[i + 1]);
  return BigInt("0x" + Buffer.from(s).toString("hex"));
}

const isHighS = (signatureBase64) =>
  derSignatureS(Buffer.from(signatureBase64, "base64")) > SECP256K1_HALF_N;


/**
 * Key material as bytes, whichever encoding the vector declares.
 *
 * secp256k1 keys are 0x-prefixed hex and the post-quantum ones are base64.
 * Measuring a hex key with base64 silently returns a plausible-looking wrong
 * number, which is exactly the class of mistake this file exists to catch.
 */
const keyBytes = (value, encoding) =>
  encoding === "hex-0x"
    ? Buffer.from(value.replace(/^0x/, ""), "hex").length
    : b64len(value);

const EXPECTED = {
  "ml-dsa-65": { pub: 1952, prv: 4032, sig: 3309, keyEncoding: "base64" },
  "falcon-512": { pub: 897, prv: 1281, sig: null, keyEncoding: "base64" },
  // pub is per-form, so it is checked in the secp256k1 section below.
  secp256k1: { pub: null, prv: 32, sig: null, keyEncoding: "hex-0x" },
};

check(vectors.length > 0, "vector file contains vectors");

// Every case a port needs must actually be present. A vectors file that
// quietly lost its non-ascii case would let every port pass while being
// broken on real data.
const REQUIRED_CASES = ["ascii", "non-ascii", "html", "float", "ordering", "onboard"];
for (const type of Object.keys(EXPECTED)) {
  const names = vectors.filter((v) => v.type === type).map((v) => v.messageName);
  for (const required of REQUIRED_CASES) {
    check(names.includes(required), `${type} has a '${required}' case`);
  }
}

for (const v of vectors) {
  const want = EXPECTED[v.type];
  const label = `${v.type} / ${v.messageName}`;
  check(!!want, `${label}: known key type`);
  if (!want) continue;

  check(
    v.keyEncoding === want.keyEncoding,
    `${label}: declares keyEncoding ${want.keyEncoding}`
  );

  const pubBytes = keyBytes(v.publicKey, v.keyEncoding);
  const prvBytes = keyBytes(v.privateKey, v.keyEncoding);

  if (want.pub !== null) {
    check(pubBytes === want.pub, `${label}: public key is ${want.pub} bytes`);
  }
  check(prvBytes === want.prv, `${label}: private key is ${want.prv} bytes`);

  const sigBytes = b64len(v.signature);
  if (v.type === "secp256k1") {
    // DER length varies with the size of r and s.
    check(sigBytes >= 64 && sigBytes <= 72, `${label}: DER signature length ${sigBytes} in 64-72`);
  } else if (want.sig !== null) {
    check(sigBytes === want.sig, `${label}: signature is ${want.sig} bytes`);
  } else {
    check(sigBytes >= 649 && sigBytes <= 662, `${label}: signature length ${sigBytes} in 649-662`);
  }

  // The declared lengths must match the actual bytes. A port may read either.
  check(v.publicKeyBytes === pubBytes, `${label}: declared publicKeyBytes matches`);
  check(v.privateKeyBytes === prvBytes, `${label}: declared privateKeyBytes matches`);
  check(v.signatureBytes === sigBytes, `${label}: declared signatureBytes matches`);
  check(
    v.messageBytes === Buffer.from(v.message, "utf8").length,
    `${label}: declared messageBytes matches the UTF-8 length`
  );

  // The point of the file.
  check(
    provider.verify(v.message, v.signature, { pkcs8pem: v.publicKey }, v.type),
    `${label}: published signature verifies`
  );

  // And a tampered message must not.
  check(
    !provider.verify(v.message + " ", v.signature, { pkcs8pem: v.publicKey }, v.type),
    `${label}: tampered message does not verify`
  );

  // NOT asserted: that re-signing reproduces the published signature.
  //
  // Both schemes are non-reproducible here. ml-dsa-65 is HEDGED in this SDK -
  // crypto.ts passes fresh extraEntropy on every sign so the library does not
  // depend on globalThis.crypto - and falcon-512 is randomised as well. FIPS
  // 204 permits both hedged and deterministic; this SDK chose hedged, so a
  // port that matches it cannot produce equal bytes and must not be asked to.
  //
  // What IS asserted is the property that actually matters: a fresh signature
  // over the same message verifies against the published public key. That is
  // what interoperability means.
  {
    const fresh = provider.sign(v.message, { pkcs8pem: v.privateKey }, v.type);
    check(
      provider.verify(v.message, fresh, { pkcs8pem: v.publicKey }, v.type),
      `${label}: a freshly made signature verifies against the published key`
    );
    check(fresh !== v.signature, `${label}: signing is hedged, so a fresh signature differs`);
  }
}

// secp256k1's encoding traps, each one a way a port can look correct against
// this file while producing keys or signatures the ledger rejects.
{
  const ec = vectors.filter((v) => v.type === "secp256k1");
  check(ec.length > 0, "secp256k1 vectors are present");

  // Both public key forms must be covered: the ledger accepts either, so a
  // port that only ever sees one will not learn to read the other.
  // The published signatures must cover BOTH S forms. A library that
  // enforces low-S on verification - which @noble/curves and libsecp256k1 do
  // by default - rejects roughly half of everything the ledger produces, and
  // a vector file that happened to contain only low-S signatures would let
  // such a port pass while being broken in production half the time.
  const highS = ec.filter((v) => isHighS(v.signature)).length;
  check(highS > 0, "secp256k1 vectors include at least one HIGH-S signature");
  check(ec.length - highS > 0, "secp256k1 vectors include at least one low-S signature");

  const forms = new Set(ec.map((v) => v.publicKeyForm));
  check(forms.has("compressed"), "secp256k1 has compressed public key vectors");
  check(forms.has("uncompressed"), "secp256k1 has uncompressed public key vectors");

  for (const v of ec) {
    const label = `secp256k1 / ${v.messageName} / ${v.publicKeyForm}`;

    // The 0x prefix is part of what the ledger stores, not decoration.
    check(v.publicKey.startsWith("0x"), `${label}: public key carries the 0x prefix`);
    check(v.privateKey.startsWith("0x"), `${label}: private key carries the 0x prefix`);

    // 66 = "0x" + 64 hex. node's ECDH.getPrivateKey() strips leading zero
    // bytes (roughly 1 key in 400); a vector published without left-padding
    // would teach every port the wrong length.
    check(v.privateKey.length === 66, `${label}: private key is left-padded to 32 bytes`);

    const expectedPubChars = v.publicKeyForm === "compressed" ? 68 : 132;
    check(
      v.publicKey.length === expectedPubChars,
      `${label}: ${v.publicKeyForm} public key is ${expectedPubChars} chars`
    );

    // SEC1 point prefix: 02/03 compressed, 04 uncompressed.
    const prefix = v.publicKey.slice(2, 4);
    check(
      v.publicKeyForm === "compressed" ? ["02", "03"].includes(prefix) : prefix === "04",
      `${label}: SEC1 point prefix ${prefix} matches ${v.publicKeyForm}`
    );

    // A DER SEQUENCE. A port emitting a raw r||s pair would be rejected by
    // the ledger with nothing but 1220 to go on.
    const der = Buffer.from(v.signature, "base64");
    check(der[0] === 0x30, `${label}: signature is DER (starts 0x30)`);
    check(der[1] === der.length - 2, `${label}: DER length header matches the body`);

    // The bytes a conforming signer must reproduce exactly. This is the
    // strongest test in the file and it exists only for secp256k1: the
    // post-quantum schemes are hedged, so their vectors can never assert more
    // than "a fresh signature verifies".
    // The constructed high-S form. Published as bytes so no port has to build
    // it -- the construction needs the curve order, and a port that sources n
    // from the wrong place produces an invalid fixture that then passes a
    // permissive verifier for the wrong reason.
    check(!!v.highSSignature, `${label}: publishes a highSSignature`);
    if (v.highSSignature) {
      check(isHighS(v.highSSignature), `${label}: the published high-S form really is high-S`);
      check(
        v.highSSignature !== v.deterministicSignature,
        `${label}: the high-S form differs from the one it was built from`
      );
      // The point of it: still a valid signature over the same message.
      check(
        provider.verify(v.message, v.highSSignature, { pkcs8pem: v.publicKey }, "secp256k1"),
        `${label}: the high-S signature verifies`
      );
      check(
        !provider.verify(v.message + " ", v.highSSignature, { pkcs8pem: v.publicKey }, "secp256k1"),
        `${label}: a tampered message does not verify against the high-S signature`
      );
    }

    check(!!v.deterministicSignature, `${label}: publishes a deterministicSignature`);
    if (v.deterministicSignature) {
      check(
        !isHighS(v.deterministicSignature),
        `${label}: the deterministic signature is low-S`
      );
      check(
        provider.verify(v.message, v.deterministicSignature, { pkcs8pem: v.publicKey }, "secp256k1"),
        `${label}: the deterministic signature verifies`
      );
      check(
        !provider.verify(v.message + " ", v.deterministicSignature, { pkcs8pem: v.publicKey }, "secp256k1"),
        `${label}: a tampered message does not verify against the deterministic signature`
      );
    }
  }
}

// Falcon key bytes must carry their 1-byte type header. Without it a JVM port
// using BouncyCastle's raw getters (896/1280) would look correct against this
// file while producing keys the ledger rejects.
for (const v of vectors.filter((x) => x.type === "falcon-512")) {
  const pub = Buffer.from(v.publicKey, "base64");
  const prv = Buffer.from(v.privateKey, "base64");
  check(pub[0] === 0x09, `${v.messageName}: falcon public key starts with 0x09`);
  check(prv[0] === 0x59, `${v.messageName}: falcon private key starts with 0x59`);
}

// The canonicalisation cases must be canonical, or they test nothing.
for (const v of vectors.filter((x) => x.messageName === "non-ascii")) {
  check(!v.message.includes("\\u"), `${v.type}: non-ascii case is raw UTF-8, not \\uXXXX escapes`);
  check(
    v.messageBytes > v.message.length,
    `${v.type}: non-ascii case really contains multibyte characters`
  );
}
for (const v of vectors.filter((x) => x.messageName === "html")) {
  check(v.message.includes("<") && v.message.includes("&"), `${v.type}: html case is not escaped`);
  check(!v.message.includes("\\u003c"), `${v.type}: html case has no unicode-escaped angle bracket`);
}
for (const v of vectors.filter((x) => x.messageName === "float")) {
  check(v.message.includes('"whole":1,'), `${v.type}: float case writes 1.0 as 1, the way JavaScript does`);
}
for (const v of vectors.filter((x) => x.messageName === "ordering")) {
  check(
    v.message.indexOf('"zebra"') < v.message.indexOf('"alpha"'),
    `${v.type}: ordering case preserves insertion order rather than sorting`
  );
}

if (failures) {
  console.error(`\n${failures} vector check(s) failed.`);
  process.exit(1);
}
console.log(`ok - all ${vectors.length} published vectors verify against this SDK.`);
