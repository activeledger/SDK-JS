// Proves the new sdk-node / sdk-web packages are actually compatible with
// the real ledger's own crypto (packages/crypto in the main activeledger
// repo, ActiveCrypto.KeyPair) - not just with each other. This is the real
// bar: a signature the ledger won't accept is useless regardless of how
// clean the split is.
//
// Runs many iterations - an earlier version of this script ran each check
// once, which had roughly even odds of missing a real bug (node:crypto/the
// ledger don't normalize signatures to low-S, and @noble/curves' verify()
// rejects high-S signatures by default - about half of all signatures hit
// this before sdk-web's provider was fixed to pass `lowS: false`).
import { createRequire } from "module";
import * as fs from "fs";
import * as path from "path";
const require = createRequire(import.meta.url);

// The ledger checkout was hardcoded to a path that does not exist - the
// real tree repeats "activeledger/" - so this script has never once run,
// which is why nothing noticed that no CI job anywhere verifies an SDK
// signature against real ledger code.
//
// Taking it from the environment also lets CI skip cleanly when there is
// no ledger checkout, rather than failing for a reason that has nothing
// to do with the code under test.
const LEDGER = process.env.ACTIVELEDGER_PATH;
if (!LEDGER) {
  console.log(
    "SKIP verify-ledger-interop: set ACTIVELEDGER_PATH to a built activeledger checkout"
  );
  process.exit(0);
}

const cryptoPath = path.join(LEDGER, "packages", "crypto", "lib", "index.js");
if (!fs.existsSync(cryptoPath)) {
  console.error(
    `No built ledger crypto at ${cryptoPath} - run 'npm run build' in the ledger checkout`
  );
  process.exit(1);
}

const { NodeCryptoProvider } = require("../packages/node/lib/index.js");
const { WebCryptoProvider } = await import("../packages/web/lib/index.js");
const { ActiveCrypto } = require(cryptoPath);

const nodeProvider = new NodeCryptoProvider();
const webProvider = new WebCryptoProvider();

function assert(condition, message, quiet = false) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    process.exitCode = 1;
  } else if (!quiet) {
    console.log(`ok - ${message}`);
  }
}

const data = JSON.stringify({ $contract: "onboard", $namespace: "default", $i: {} });
const ITERATIONS = 100;

// Ledger generates a keypair, node/web providers sign - ledger's own KeyPair.verify() must accept both
for (let i = 0; i < ITERATIONS; i++) {
  const ledgerKey = new ActiveCrypto.KeyPair("secp256k1");
  const generated = ledgerKey.generate();
  const ledgerVerifyKey = new ActiveCrypto.KeyPair("secp256k1", generated.pub.pkcs8pem);

  const keyDetails = { pub: { pkcs8pem: generated.pub.pkcs8pem }, prv: { pkcs8pem: generated.prv.pkcs8pem } };

  const nodeSig = nodeProvider.sign(data, keyDetails.prv);
  assert(ledgerVerifyKey.verify(data, nodeSig), `ledger verifies a signature from sdk-node's provider (iteration ${i})`, true);

  const webSig = webProvider.sign(data, keyDetails.prv);
  assert(ledgerVerifyKey.verify(data, webSig), `ledger verifies a signature from sdk-web's provider (iteration ${i})`, true);
}
assert(true, `${ITERATIONS}x ledger verifies signatures from both sdk-node and sdk-web, over ledger-generated keys`);

// sdk-node/sdk-web generate a keypair, ledger's own KeyPair.sign() signs - node/web providers must verify it
for (let i = 0; i < ITERATIONS; i++) {
  const key = nodeProvider.generate();
  const ledgerSignKey = new ActiveCrypto.KeyPair("secp256k1", key.prv.pkcs8pem);
  const ledgerSig = ledgerSignKey.sign(data);

  assert(nodeProvider.verify(data, ledgerSig, key.pub), `sdk-node verifies a ledger-produced signature (iteration ${i})`, true);
  assert(webProvider.verify(data, ledgerSig, key.pub), `sdk-web verifies a ledger-produced signature (iteration ${i})`, true);
}
assert(true, `${ITERATIONS}x both sdk-node and sdk-web verify signatures the ledger produced`);

// ---------------------------------------------------------------------------
// Post-quantum: ml-dsa-65 and falcon-512.
//
// Far fewer iterations than secp256k1 above, deliberately. That loop runs 100x
// because ECDSA signatures are randomised and roughly half hit the high-S case
// that once broke sdk-web. The PQ schemes have no equivalent trap: ml-dsa-65
// with a bare key is fully deterministic, and falcon-512 varies only in length.
// A handful of rounds is enough to catch a wiring error, and these keys are
// 1952-4032 bytes, so 100x would be slow for no added signal.
const PQ_ITERATIONS = 5;
const PQ_TYPES = ["ml-dsa-65", "falcon-512"];

// Expected byte lengths, so a wrong-length key is caught HERE rather than
// reaching a node and coming back as 1220 "Signature Incorrect".
const PQ_LENGTHS = {
  "ml-dsa-65": { pub: 1952, prv: 4032, sig: 3309 },
  "falcon-512": { pub: 897, prv: 1281, sig: null }, // variable, 649-662
};

const b64len = (s) => Buffer.from(s, "base64").length;

for (const type of PQ_TYPES) {
  const want = PQ_LENGTHS[type];

  // Ledger-generated keys, SDK-produced signatures.
  for (let i = 0; i < PQ_ITERATIONS; i++) {
    const ledgerKey = new ActiveCrypto.KeyPair(type);
    const generated = ledgerKey.generate();

    assert(b64len(generated.pub.pkcs8pem) === want.pub, `${type} ledger public key is ${want.pub} bytes`, i > 0);
    assert(b64len(generated.prv.pkcs8pem) === want.prv, `${type} ledger private key is ${want.prv} bytes`, i > 0);

    const ledgerVerifyKey = new ActiveCrypto.KeyPair(type, generated.pub.pkcs8pem);
    const prv = { pkcs8pem: generated.prv.pkcs8pem };
    const pub = { pkcs8pem: generated.pub.pkcs8pem };

    const nodeSig = nodeProvider.sign(data, prv, type);
    assert(ledgerVerifyKey.verify(data, nodeSig), `${type}: ledger verifies an sdk-node signature (iteration ${i})`, true);

    const webSig = webProvider.sign(data, prv, type);
    assert(ledgerVerifyKey.verify(data, webSig), `${type}: ledger verifies an sdk-web signature (iteration ${i})`, true);

    if (want.sig !== null) {
      assert(b64len(nodeSig) === want.sig, `${type} signature is ${want.sig} bytes`, i > 0);
    } else {
      const len = b64len(nodeSig);
      assert(len >= 649 && len <= 662, `${type} signature length ${len} is in the expected 649-662 range`, i > 0);
    }

    // Negative: a tampered message must not verify.
    assert(!ledgerVerifyKey.verify(data + " ", nodeSig), `${type}: ledger rejects a tampered message`, i > 0);
    assert(!nodeProvider.verify(data + " ", nodeSig, pub, type), `${type}: sdk-node rejects a tampered message`, i > 0);
  }
  assert(true, `${PQ_ITERATIONS}x ${type}: ledger verifies signatures from both sdk-node and sdk-web`);

  // SDK-generated keys, ledger-produced signatures.
  for (let i = 0; i < PQ_ITERATIONS; i++) {
    const key = nodeProvider.generate(undefined, type);

    assert(b64len(key.pub.pkcs8pem) === want.pub, `${type} sdk public key is ${want.pub} bytes`, i > 0);
    assert(b64len(key.prv.pkcs8pem) === want.prv, `${type} sdk private key is ${want.prv} bytes`, i > 0);

    const ledgerSignKey = new ActiveCrypto.KeyPair(type, key.prv.pkcs8pem);
    const ledgerSig = ledgerSignKey.sign(data);

    assert(nodeProvider.verify(data, ledgerSig, key.pub, type), `${type}: sdk-node verifies a ledger signature (iteration ${i})`, true);
    assert(webProvider.verify(data, ledgerSig, key.pub, type), `${type}: sdk-web verifies a ledger signature (iteration ${i})`, true);
  }
  assert(true, `${PQ_ITERATIONS}x ${type}: both sdk-node and sdk-web verify signatures the ledger produced`);
}

// Cross-scheme confusion must be a clean false, never a throw - a caller
// should not have to distinguish "invalid" from "malformed".
{
  const mldsa = new ActiveCrypto.KeyPair("ml-dsa-65");
  const mldsaKeys = mldsa.generate();
  const falcon = new ActiveCrypto.KeyPair("falcon-512");
  const falconKeys = falcon.generate();

  const falconSig = nodeProvider.sign(data, { pkcs8pem: falconKeys.prv.pkcs8pem }, "falcon-512");

  let threw = false;
  let result = true;
  try {
    result = nodeProvider.verify(data, falconSig, { pkcs8pem: mldsaKeys.pub.pkcs8pem }, "ml-dsa-65");
  } catch {
    threw = true;
  }
  assert(!threw, "a falcon signature checked against an ml-dsa key does not throw");
  assert(result === false, "a falcon signature checked against an ml-dsa key returns false");
}

if (process.exitCode) {
  console.error("\nLedger interop check FAILED");
  process.exit(1);
} else {
  console.log("\nAll sdk <-> ledger interop checks passed.");
}
