// Proves that verify-seed-vectors.mjs actually detects a changed derivation.
//
// It exists because that script once did not. Everything in it recomputed
// HKDF inline and called noble directly, so it compared the vector FILE
// against a second copy of the formula and never against the SDK's own code -
// and it stayed green with the post-quantum derivation deliberately broken.
// The jest suite caught that, but a guard which only works because a
// different guard exists is not one, and this script is the artefact the
// other six SDKs are modelled on.
//
// So the guard now has evidence rather than a claim. Each mutation below is
// applied to the BUILT module the verifier loads, the verifier is re-run, and
// it must fail.
//
// EVERY MUTATION ASSERTS THAT IT MUTATED. A replacement whose pattern no
// longer matches is a silent no-op, and a mutation that does not mutate reads
// exactly like a passing guard - the verifier is handed unchanged code and
// correctly says nothing is wrong. Both this repository and a downstream team
// hit that false pass independently, in opposite directions, within a day.

import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const TARGET = path.join(here, "..", "packages", "node", "lib", "recovery.js");
const VERIFIER = path.join(here, "verify-seed-vectors.mjs");

if (!fs.existsSync(TARGET)) {
  console.error(`No built module at ${TARGET} - run 'npm run build' first`);
  process.exit(1);
}

// Each is a real way the derivation could drift, not a synthetic edit: the
// domain-separation tag, the hash, the secp256k1 HMAC key, and the truncation
// that makes a 64-byte digest a 32-byte scalar.
const MUTATIONS = [
  { name: "post-quantum info string", from: "activeledger-seed-v1:", to: "activeledger-seed-v2:" },
  { name: "post-quantum hash", from: 'crypto.hkdfSync("sha512"', to: 'crypto.hkdfSync("sha256"' },
  { name: "secp256k1 HMAC key", from: '"Bitcoin seed"', to: '"Bitcoin seedX"' },
  { name: "secp256k1 truncation", from: ".subarray(0, 32)", to: ".subarray(0, 31)" },
];

const original = fs.readFileSync(TARGET, "utf8");
let failures = 0;

// Restored even on an exception or a Ctrl-C, or the working tree is left
// holding a deliberately broken build that every later run inherits.
const restore = () => fs.writeFileSync(TARGET, original);
process.on("exit", restore);
process.on("SIGINT", () => process.exit(130));

try {
  for (const { name, from, to } of MUTATIONS) {
    if (!original.includes(from)) {
      console.error(`FAIL: ${name}: pattern ${JSON.stringify(from)} is not in the built module`);
      console.error("      The mutation could not be applied, so this proves nothing. Fix the");
      console.error("      pattern - do not delete the case.");
      failures++;
      continue;
    }

    const mutated = original.replace(from, to);

    // The assertion that makes the rest meaningful.
    if (mutated === original) {
      console.error(`FAIL: ${name}: replacement did not change the file`);
      failures++;
      continue;
    }

    fs.writeFileSync(TARGET, mutated);

    let caught = false;
    try {
      execFileSync("node", [VERIFIER], { stdio: "pipe" });
    } catch {
      caught = true;
    } finally {
      fs.writeFileSync(TARGET, original);
    }

    if (caught) {
      console.log(`  ok - ${name} is detected`);
    } else {
      console.error(`FAIL: ${name} was NOT detected - the verifier would ship this change`);
      failures++;
    }
  }

  // The verifier must still pass on unmutated code, or "detected" above could
  // just mean it fails on everything.
  try {
    execFileSync("node", [VERIFIER], { stdio: "pipe" });
    console.log("  ok - and it passes on unmodified code");
  } catch {
    console.error("FAIL: the verifier fails even without a mutation");
    failures++;
  }
} finally {
  restore();
}

if (failures) {
  console.error(`\n${failures} seed-guard check(s) failed`);
  process.exit(1);
}

console.log(`seed guard OK - ${MUTATIONS.length} derivation changes each detected`);
