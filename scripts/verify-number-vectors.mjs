// Checks the committed number vectors against JSON.stringify.
//
// Trivial by construction - the file is generated from JSON.stringify - and
// that is the point. It catches a file that was hand-edited, truncated,
// merged badly, or regenerated on a build where something had been patched.
// Six other SDK repositories treat it as the definition of correct, so it is
// checked on every run rather than on the day it was written.

import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = path.join(here, "..", "vectors", "number-vectors.json");

if (!fs.existsSync(VECTORS)) {
  console.error(`No number vector file at ${VECTORS} - run 'npm run vectors:numbers'`);
  process.exit(1);
}

const doc = JSON.parse(fs.readFileSync(VECTORS, "utf8"));
let failures = 0;
const check = (condition, message) => {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    failures++;
  }
};

check(Array.isArray(doc.vectors) && doc.vectors.length >= 20, "number vectors missing or too few");
check(typeof doc.header === "string" && doc.header.includes("ECMA-262"), "header must state the rule");

for (const v of doc.vectors) {
  check(
    JSON.stringify(v.value) === v.expected,
    `${v.name}: expected ${JSON.stringify(v.expected)}, JSON.stringify gives ${JSON.stringify(JSON.stringify(v.value))}`,
  );
}

// A file that lost its boundary cases would pass everything above while
// testing nothing that matters - those are where implementations part company.
const names = new Set(doc.vectors.map((v) => v.name));
for (const required of ["int-1e20", "int-1e21", "small-1e-6", "small-1e-7", "negative-zero"]) {
  check(names.has(required), `the ${required} boundary case is missing`);
}

check(
  doc.vectors.some((v) => v.expected.includes("e+")) && doc.vectors.some((v) => v.expected.includes("e-")),
  "no exponent-form vectors - the case six SDKs got wrong is untested",
);

if (failures) {
  console.error(`\n${failures} number vector check(s) failed`);
  process.exit(1);
}

console.log(`number vectors OK - ${doc.vectors.length} checked against JSON.stringify`);
