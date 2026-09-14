/**
 * Do post-quantum keys and signatures cross between sdk-web and sdk-node?
 *
 * A browser or React Native client generates a key with one provider; a
 * server, and the ledger, verify it with another. If the two disagree about
 * encoding or entropy then every signature made on one side is worthless on
 * the other - and neither package's own tests would show it.
 *
 * Deliberately plain node against the BUILT packages rather than Jest
 * against source: that is what consumers install, and Jest's ESM runtime
 * cannot load sdk-node's CommonJS build at all because it require()s an
 * ESM-only dependency - something node has done fine since 20.19.
 */
import { WebCryptoProvider } from "../packages/web/lib/index.js";
import pkg from "../packages/node/lib/index.js";
const { NodeCryptoProvider } = pkg;

const web = new WebCryptoProvider();
const node = new NodeCryptoProvider();
const TYPES = ["ml-dsa-65", "falcon-512"];

let failures = 0;
const check = (name, got, want = true) => {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${name}`);
};

console.log("\nsdk-web <-> sdk-node post-quantum interop");
console.log("=".repeat(58));

for (const type of TYPES) {
  console.log(`\n${type}`);
  const data = JSON.stringify({ $i: { alice: { amount: "100" } } });

  const w = web.generate(false, type);
  const n = node.generate(false, type);

  check("web key + web signature verifies in node",
    node.verify(data, web.sign(data, w.prv, type), w.pub, type));
  check("node key + node signature verifies in web",
    web.verify(data, node.sign(data, n.prv, type), n.pub, type));
  check("web key signed in node verifies in web",
    web.verify(data, node.sign(data, w.prv, type), w.pub, type));
  check("node key signed in web verifies in node",
    node.verify(data, web.sign(data, n.prv, type), n.pub, type));
  check("public key encodings are the same length",
    Buffer.from(w.pub.pkcs8pem, "base64").length === Buffer.from(n.pub.pkcs8pem, "base64").length);
  check("private key encodings are the same length",
    Buffer.from(w.prv.pkcs8pem, "base64").length === Buffer.from(n.prv.pkcs8pem, "base64").length);
  check("a tampered payload is rejected across packages",
    node.verify(JSON.stringify({ tampered: true }), web.sign(data, w.prv, type), w.pub, type), false);
  check("a different key of the same type does not verify",
    node.verify(data, web.sign(data, web.generate(false, type).prv, type), n.pub, type), false);
}

// secp256k1 interop, properly - same key both sides
{
  console.log("\nsecp256k1 (unchanged behaviour)");
  const data = "regression";
  const w = web.generate();
  check("web key + web signature verifies in node",
    node.verify(data, web.sign(data, w.prv), w.pub));
  const n = node.generate();
  check("node key + node signature verifies in web",
    web.verify(data, node.sign(data, n.prv), n.pub));
}

console.log(`\n${failures ? failures + " FAILED" : "all interop checks passed"}\n`);
process.exit(failures ? 1 : 0);
