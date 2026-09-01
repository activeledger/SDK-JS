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
const require = createRequire(import.meta.url);

const { NodeCryptoProvider } = require("../packages/node/lib/index.js");
const { WebCryptoProvider } = await import("../packages/web/lib/index.js");
const { ActiveCrypto } = require("/home/adamw/git/activeledger/packages/crypto/lib/index.js");

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

if (process.exitCode) {
  console.error("\nLedger interop check FAILED");
  process.exit(1);
} else {
  console.log("\nAll sdk <-> ledger interop checks passed.");
}
