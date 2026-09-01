// Proves the new sdk-node / sdk-web packages are actually compatible with
// the real ledger's own crypto (packages/crypto in the main activeledger
// repo, ActiveCrypto.KeyPair) - not just with each other. This is the real
// bar: a signature the ledger won't accept is useless regardless of how
// clean the split is.
import { createRequire } from "module";
const require = createRequire(import.meta.url);

const { NodeCryptoProvider } = require("../packages/node/lib/index.js");
const { WebCryptoProvider } = await import("../packages/web/lib/index.js");
const { ActiveCrypto } = require("/home/adamw/git/activeledger/packages/crypto/lib/index.js");

const nodeProvider = new NodeCryptoProvider();
const webProvider = new WebCryptoProvider();

function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    process.exitCode = 1;
  } else {
    console.log(`ok - ${message}`);
  }
}

const data = JSON.stringify({ $contract: "onboard", $namespace: "default", $i: {} });

// Ledger generates a keypair, node/web providers sign - ledger's own KeyPair.verify() must accept both
{
  const ledgerKey = new ActiveCrypto.KeyPair("secp256k1");
  const generated = ledgerKey.generate();
  const ledgerVerifyKey = new ActiveCrypto.KeyPair("secp256k1", generated.pub.pkcs8pem);

  const keyDetails = { pub: { pkcs8pem: generated.pub.pkcs8pem }, prv: { pkcs8pem: generated.prv.pkcs8pem } };

  const nodeSig = nodeProvider.sign(data, keyDetails.prv);
  assert(ledgerVerifyKey.verify(data, nodeSig), "ledger verifies a signature from sdk-node's provider, over a ledger-generated key");

  const webSig = webProvider.sign(data, keyDetails.prv);
  assert(ledgerVerifyKey.verify(data, webSig), "ledger verifies a signature from sdk-web's provider, over a ledger-generated key");
}

// sdk-node/sdk-web generate a keypair, ledger's own KeyPair.sign() signs - node/web providers must verify it
{
  const key = nodeProvider.generate();
  const ledgerSignKey = new ActiveCrypto.KeyPair("secp256k1", key.prv.pkcs8pem);
  const ledgerSig = ledgerSignKey.sign(data);

  assert(nodeProvider.verify(data, ledgerSig, key.pub), "sdk-node verifies a signature the ledger produced, over an sdk-node-generated key");
  assert(webProvider.verify(data, ledgerSig, key.pub), "sdk-web verifies a signature the ledger produced, over an sdk-node-generated key");
}

if (process.exitCode) {
  console.error("\nLedger interop check FAILED");
  process.exit(1);
} else {
  console.log("\nAll sdk <-> ledger interop checks passed.");
}
