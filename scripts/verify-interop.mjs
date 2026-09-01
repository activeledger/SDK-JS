// Cross-package signature compatibility check: proves that a signature
// produced by sdk-node's node:crypto-based provider verifies successfully
// under sdk-web's @noble/curves-based provider, and vice versa - the whole
// point of keeping both on SHA-256 + DER ECDSA over secp256k1. Not part of
// the Jest suite since sdk-web is ESM-only (its @noble/curves dependency
// can't be require()'d from ts-jest's CommonJS runtime) - run directly with
// `node scripts/verify-interop.mjs` after `npm run build`.
import { createRequire } from "module";
const require = createRequire(import.meta.url);

const { NodeCryptoProvider } = require("../packages/node/lib/index.js");
const { WebCryptoProvider } = await import("../packages/web/lib/index.js");

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

// Node generates, node signs, web verifies
{
  const key = nodeProvider.generate();
  const signature = nodeProvider.sign(data, key.prv);
  assert(webProvider.verify(data, signature, key.pub), "node-generated key + node signature verifies under web provider");
  assert(nodeProvider.verify(data, signature, key.pub), "node-generated key + node signature verifies under node provider (self)");
}

// Web generates, web signs, node verifies
{
  const key = webProvider.generate();
  const signature = webProvider.sign(data, key.prv);
  assert(nodeProvider.verify(data, signature, key.pub), "web-generated key + web signature verifies under node provider");
  assert(webProvider.verify(data, signature, key.pub), "web-generated key + web signature verifies under web provider (self)");
}

// Node generates + signs, but web verifies against a TAMPERED payload - must fail
{
  const key = nodeProvider.generate();
  const signature = nodeProvider.sign(data, key.prv);
  assert(!webProvider.verify(data + "tampered", signature, key.pub), "web provider rejects a node signature over tampered data");
}

// Compressed public key round-trip across both providers
{
  const key = nodeProvider.generate(true);
  assert(/^0x0[23]/.test(key.pub.pkcs8pem), "node provider compressed pubkey has 02/03 prefix");
  const signature = nodeProvider.sign(data, key.prv);
  assert(webProvider.verify(data, signature, key.pub), "compressed node-generated key verifies under web provider");
}

if (process.exitCode) {
  console.error("\nInterop check FAILED");
  process.exit(1);
} else {
  console.log("\nAll cross-package interop checks passed.");
}
