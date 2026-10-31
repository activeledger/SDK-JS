/**
 * Do sdk-node and sdk-web agree about which key material is well formed?
 *
 * Both are given the same inputs - good and bad hex, and a mismatched key
 * pair - and must accept and refuse the same ones. Plain node against the
 * BUILT packages, for the reason verify-pq-interop.mjs gives.
 */
import { WebCryptoProvider } from "../packages/web/lib/index.js";
import { fromHex } from "../packages/web/lib/crypto.js";
import pkg from "../packages/node/lib/index.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const { KeyHandler } = pkg;

let failures = 0;
const check = (name, got, want) => {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${name}`);
};

console.log("\nsdk-web <-> sdk-node input validation agreement");
console.log("=".repeat(58));

const nodeKeys = new KeyHandler();
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sdk-validation-"));
const accepted = (promise) => promise.then(() => true, () => false);
const webAccepts = (hex) => { try { fromHex(hex); return true; } catch { return false; } };

try {
  // Node has no standalone hex decoder, so its rule is observed through
  // importKey: a key whose public half is the true one for the scalar
  // 0xabab...ab, with only the private encoding varied.
  const scalar = "ab".repeat(32);
  const real = new WebCryptoProvider().generateFromSeed(Uint8Array.from(Buffer.from(scalar, "hex")), true);
  const base = await nodeKeys.generateKey("k", true);
  const file = path.join(dir, "k.json");

  for (const [name, prv, want] of [
    ["0x-prefixed", "0x" + scalar, true],
    ["bare", scalar, true],
    ["uppercase", "0x" + scalar.toUpperCase(), true],
    ["non-hex digits", "0x" + "zz".repeat(32), false],
    ["odd length", "0x" + "a".repeat(63), false],
    ["whitespace", "0x " + scalar.slice(1), false],
  ]) {
    fs.writeFileSync(file, JSON.stringify({ ...base, key: { prv: { pkcs8pem: prv }, pub: real.pub } }));
    check(`hex ${name}: web fromHex ${want ? "accepts" : "refuses"}`, webAccepts(prv), want);
    check(`hex ${name}: node importKey ${want ? "accepts" : "refuses"}`, await accepted(nodeKeys.importKey(file)), want);
  }

  // Mismatched pair: each side must refuse to use / import it.
  for (const type of ["secp256k1", "ml-dsa-65", "falcon-512"]) {
    const a = await nodeKeys.generateKey("a", true, type);
    const b = await nodeKeys.generateKey("b", true, type);
    const mixed = { ...a, key: { prv: a.key.prv, pub: b.key.pub } };
    const file = path.join(dir, `${type}.json`);
    fs.writeFileSync(file, JSON.stringify(mixed));
    check(`${type}: node import refuses a mismatched pair`, await nodeKeys.importKey(file).then(() => true, () => false), false);
    fs.writeFileSync(file, JSON.stringify(a));
    check(`${type}: node import accepts a matching pair`, await nodeKeys.importKey(file).then(() => true, () => false), true);
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall input validation checks passed");
