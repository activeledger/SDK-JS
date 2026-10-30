// Smoke test of the BUILT, PACKED artifacts, the way a user consumes them.
//
// Builds the workspace, `npm pack`s sdk-core, sdk-node and sdk-web, installs
// the tarballs into a fresh temporary project, then - from that project, with
// no access to this repo's sources - generates a key of each type, builds and
// signs a transaction, verifies the signature, and sends it to an in-process
// loopback HTTP server that mimics a node's reply (a committed one and a
// rejected one that still comes back as HTTP 200).
//
// Run with `node scripts/smoke-pack.mjs` from the repo root. The install runs
// with --offline, so it needs the dependencies in npm's cache (any prior
// `npm ci` leaves them there); nothing else touches the network.
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const scratch = mkdtempSync(join(tmpdir(), "sdk-smoke-"));
const tarballs = join(scratch, "tarballs");
const project = join(scratch, "project");
mkdirSync(tarballs);
mkdirSync(project);

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
  if (result.status !== 0) {
    console.error(`FAIL: ${command} ${args.join(" ")}\n${result.stdout}\n${result.stderr}`);
    process.exit(1);
  }
  return result.stdout;
}

try {
  run("npm", ["run", "build"], root);
  console.log("ok - built");

  for (const pkg of ["core", "node", "web"]) {
    run("npm", ["pack", "-w", `packages/${pkg}`, "--pack-destination", tarballs], root);
  }
  const files = readdirSync(tarballs).map((f) => join(tarballs, f));
  if (files.length !== 3) {
    console.error(`FAIL: expected 3 tarballs, got ${files.join(", ")}`);
    process.exit(1);
  }
  console.log("ok - packed " + readdirSync(tarballs).join(", "));

  writeFileSync(join(project, "package.json"), JSON.stringify({ name: "smoke", private: true, type: "module" }));
  run("npm", ["install", "--offline", "--no-audit", "--no-fund", ...files], project);
  console.log("ok - installed into a fresh project");

  writeFileSync(join(project, "consumer.mjs"), consumer());
  const out = spawnSync("node", ["consumer.mjs"], { cwd: project, encoding: "utf8" });
  process.stdout.write(out.stdout);
  process.stderr.write(out.stderr);
  if (out.status !== 0) {
    process.exit(1);
  }
  console.log("smoke test passed");
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

// What a user's script looks like: only package names, never repo paths.
function consumer() {
  return `
import http from "node:http";
import assert from "node:assert/strict";
import * as nodeSdk from "@activeledger/sdk-node";
import * as webSdk from "@activeledger/sdk-web";

const sdks = { node: nodeSdk, web: webSdk };

// A stand-in for a node: records what it is sent, answers from \`reply\`.
let reply;
const received = [];
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    received.push({ method: req.method, type: req.headers["content-type"], body: JSON.parse(body) });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(reply));
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;

const committed = { $umid: "umid-1", $summary: { total: 1, vote: 1, commit: 1 }, $streams: { new: [{ id: "s1", name: "alice" }], updated: [] } };
const rejected = { $umid: "umid-2", $summary: { total: 1, vote: 0, commit: 0 }, $streams: { new: [], updated: [] } };

try {
  for (const [platform, sdk] of Object.entries(sdks)) {
    const keys = new sdk.KeyHandler();
    const txs = new sdk.TransactionHandler();
    const provider = platform === "node" ? new sdk.NodeCryptoProvider() : new sdk.WebCryptoProvider();
    const conn = new sdk.Connection("http", "127.0.0.1", port);

    for (const type of ["secp256k1", "ml-dsa-65", "falcon-512"]) {
      const label = platform + "/" + type;
      const key = await keys.generateKey("alice", false, type);
      assert.equal(key.type, type, label + ": key type");

      const tx = await txs.buildOnboardKeyTx(key);
      assert.equal(tx.$tx.$i.alice.publicKey, key.key.pub.pkcs8pem, label + ": tx carries the public key");
      assert.ok(provider.verify(JSON.stringify(tx.$tx), tx.$sigs.alice, key.key.pub, type), label + ": signature verifies");
      assert.ok(!provider.verify(JSON.stringify({ ...tx.$tx, $contract: "other" }), tx.$sigs.alice, key.key.pub, type), label + ": tampered body fails");

      // A committed reply, then a rejected one that is still an HTTP 200.
      reply = committed;
      received.length = 0;
      const ok = await conn.sendTransaction(tx);
      assert.deepEqual(ok, committed, label + ": committed reply");
      assert.equal(received.length, 1, label + ": one request");
      assert.equal(received[0].method, "POST", label + ": POST");
      assert.match(received[0].type, /application\\/json/, label + ": JSON content type");
      assert.deepEqual(received[0].body, tx, label + ": server saw the signed tx");
      assert.ok(ok.$summary.commit === ok.$summary.total, label + ": committed");

      reply = rejected;
      const no = await conn.sendTransaction(tx);
      assert.deepEqual(no, rejected, label + ": rejected reply");
      assert.ok(no.$summary.commit < no.$summary.total, label + ": rejected despite HTTP 200");
      console.log("ok - " + label + ": key, tx, signature, committed + rejected replies");
    }
  }

  // Cross-package: a node-signed secp256k1 signature verifies under web.
  const nk = await new nodeSdk.KeyHandler().generateKey("x");
  const sig = new nodeSdk.NodeCryptoProvider().sign("payload", nk.key.prv);
  assert.ok(new webSdk.WebCryptoProvider().verify("payload", sig, nk.key.pub), "node signature verifies in web");
  console.log("ok - node-signed signature verifies in sdk-web");
} finally {
  server.close();
}
`;
}
