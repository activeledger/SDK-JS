// Verifies BIP-39 recovery-phrase key derivation:
// 1. legacy mode reproduces the EXACT same private key the original,
//    published @activeledger/sdk-bip39 package derives for a given phrase
//    (proving backward compatibility for anyone with an existing phrase).
// 2. the new default (non-legacy) mode derives IDENTICAL keys on sdk-node
//    and sdk-web for the same phrase (proving cross-platform parity for
//    the standard BIP-39 seed + BIP-32 master-key scheme).
// 3. default mode and legacy mode genuinely produce DIFFERENT keys for the
//    same phrase (proving the flag actually switches derivation, not just
//    relabels the same one).
import { createRequire } from "module";
const require = createRequire(import.meta.url);

const { KeyHandler: NodeKeyHandler } = require("../packages/node/lib/index.js");
const { KeyHandler: WebKeyHandler } = await import("../packages/web/lib/index.js");
const { KeyHandler: OldAddonKeyHandler } = require("../../SDK-NodeJS-BIP39/lib/index.js");

const nodeKeys = new NodeKeyHandler();
const webKeys = new WebKeyHandler();
const oldAddonKeys = new OldAddonKeyHandler();

function assert(condition, message, quiet = false) {
  if (!condition) {
    console.error(`FAIL: ${message}`);
    process.exitCode = 1;
  } else if (!quiet) {
    console.log(`ok - ${message}`);
  }
}

const TEST_PHRASES = [
  "legal winner thank year wave sausage worth useful legal winner thank yellow",
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
];

for (const phrase of TEST_PHRASES) {
  const oldKey = await oldAddonKeys.restoreBIP39Key("k", phrase);
  const newNodeLegacy = await nodeKeys.restoreBIP39Key("k", phrase, { legacy: true });
  const newWebLegacy = await webKeys.restoreBIP39Key("k", phrase, { legacy: true });

  assert(
    newNodeLegacy.key.prv.pkcs8pem.replace(/^0x0+/, "0x") === oldKey.key.prv.pkcs8pem.replace(/^0x0+/, "0x"),
    `sdk-node legacy mode matches the old sdk-bip39 addon's private key for "${phrase.split(" ").slice(0, 3).join(" ")}..."`,
  );
  assert(
    newWebLegacy.key.prv.pkcs8pem.replace(/^0x0+/, "0x") === oldKey.key.prv.pkcs8pem.replace(/^0x0+/, "0x"),
    `sdk-web legacy mode matches the old sdk-bip39 addon's private key for "${phrase.split(" ").slice(0, 3).join(" ")}..."`,
  );
  assert(
    newNodeLegacy.key.prv.pkcs8pem === newWebLegacy.key.prv.pkcs8pem,
    `sdk-node and sdk-web legacy mode agree byte-for-byte (both zero-padded, unlike the old addon) for "${phrase.split(" ").slice(0, 3).join(" ")}..."`,
  );

  const newNodeDefault = await nodeKeys.restoreBIP39Key("k", phrase);
  const newWebDefault = await webKeys.restoreBIP39Key("k", phrase);

  assert(
    newNodeDefault.key.prv.pkcs8pem === newWebDefault.key.prv.pkcs8pem,
    `sdk-node and sdk-web default (BIP-32 master-key) mode agree byte-for-byte for "${phrase.split(" ").slice(0, 3).join(" ")}..."`,
  );
  assert(
    newNodeDefault.key.prv.pkcs8pem !== newNodeLegacy.key.prv.pkcs8pem,
    `default mode derives a DIFFERENT key than legacy mode for the same phrase (the flag genuinely switches schemes)`,
  );

  // Sanity: the derived key actually signs/verifies correctly on both platforms
  const { NodeCryptoProvider } = require("../packages/node/lib/index.js");
  const { WebCryptoProvider } = await import("../packages/web/lib/index.js");
  const nodeProvider = new NodeCryptoProvider();
  const webProvider = new WebCryptoProvider();
  const data = "test transaction body";
  const sig = nodeProvider.sign(data, newNodeDefault.key.prv);
  assert(webProvider.verify(data, sig, newNodeDefault.key.pub), `default-mode-derived key from sdk-node actually signs and cross-verifies under sdk-web`);
}

// Passphrase actually changes the derived key (default mode only - legacy has no passphrase concept)
{
  const phrase = TEST_PHRASES[0];
  const noPass = await nodeKeys.restoreBIP39Key("k", phrase);
  const withPass = await nodeKeys.restoreBIP39Key("k", phrase, { passphrase: "extra protection" });
  assert(noPass.key.prv.pkcs8pem !== withPass.key.prv.pkcs8pem, "an optional passphrase changes the derived default-mode key");
}

// Compressed flag still works for BIP-39-derived keys too
{
  const phrase = TEST_PHRASES[0];
  const compressed = await nodeKeys.restoreBIP39Key("k", phrase, { compressed: true });
  assert(/^0x0[23][0-9a-f]{64}$/.test(compressed.key.pub.pkcs8pem), "compressed option produces a compressed pubkey for BIP-39-derived keys");
}

if (process.exitCode) {
  console.error("\nBIP-39 interop check FAILED");
  process.exit(1);
} else {
  console.log("\nAll BIP-39 checks passed.");
}
