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

const EXPECTED = {
  "ml-dsa-65": { pub: 1952, prv: 4032, sig: 3309 },
  "falcon-512": { pub: 897, prv: 1281, sig: null },
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

  check(b64len(v.publicKey) === want.pub, `${label}: public key is ${want.pub} bytes`);
  check(b64len(v.privateKey) === want.prv, `${label}: private key is ${want.prv} bytes`);

  const sigBytes = b64len(v.signature);
  if (want.sig !== null) {
    check(sigBytes === want.sig, `${label}: signature is ${want.sig} bytes`);
  } else {
    check(sigBytes >= 649 && sigBytes <= 662, `${label}: signature length ${sigBytes} in 649-662`);
  }

  // The declared lengths must match the actual bytes. A port may read either.
  check(v.publicKeyBytes === b64len(v.publicKey), `${label}: declared publicKeyBytes matches`);
  check(v.privateKeyBytes === b64len(v.privateKey), `${label}: declared privateKeyBytes matches`);
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
