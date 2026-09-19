<img src="https://github.com/activeledger/activeledger/blob/master/docs/assets/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger - SDK

Two packages for connecting a JavaScript/TypeScript application to an Activeledger network:

| Package                                                     | For                                       | Signing                                                                     |
| ------------------------------------------------------------ | ------------------------------------------ | ---------------------------------------------------------------------------- |
| [`@activeledger/sdk-node`](./packages/node)                  | Node.js applications                       | `node:crypto` (built in, no external crypto dependency)                     |
| [`@activeledger/sdk-web`](./packages/web)                    | Browsers and React Native                  | [`@noble/curves`](https://github.com/paulmillr/noble-curves) (audited, pure JS, no native dependency) |
| [`@activeledger/sdk-core`](./packages/core)                   | Shared internals - not installed directly  | -                                                                            |

Both packages share the same API shape (`KeyHandler`, `TransactionHandler`, `Connection`, `LedgerEvents`) and produce signatures that verify identically against the ledger and against each other - a key made with one package works with the other.

## Post-quantum keys

**Activeledger identities can be secured against quantum attack today.** As of SDK 2.1.0 and Activeledger 4.7.0, both packages can generate and sign with two post-quantum schemes alongside secp256k1:

| `KeyType`                | Scheme                        | Standard                    | Signature   |
| ------------------------ | ----------------------------- | --------------------------- | ----------- |
| `KeyType.MLDSA65`        | ML-DSA-65 (Dilithium)         | **FIPS 204** - finalised    | 3309 bytes  |
| `KeyType.Falcon512`      | Falcon-512 (FN-DSA)           | Draft                       | 649-662 bytes |
| `KeyType.EllipticCurve`  | secp256k1 ECDSA               | The default                 | ~71 bytes   |

Selecting one is a single argument - everything after that is unchanged:

```typescript
import { KeyHandler, KeyType } from "@activeledger/sdk-node";
// (or "@activeledger/sdk-web" - identical API)

const keys = new KeyHandler();

// Quantum-safe identity. The type is FIXED at creation and recorded on the
// ledger, so choose it here - an identity cannot be converted later.
const key = await keys.generateKey("my-key", false, KeyType.MLDSA65);
await keys.onboardKey(key, connection);

// Nothing else changes. Transactions sign and send exactly as before -
// TransactionHandler reads the scheme off the key.
const tx = await new TransactionHandler().labelledTransaction(
  key, "default", "mycontract", "input", { amount: 1 }, "stream-id",
);
await connection.sendTransaction(tx);
```

The second argument is `compressed`, which only means anything for secp256k1 and is ignored by the post-quantum schemes. It sits before the type so that existing `generateKey(name, true)` calls keep working unchanged.

### Which one should you pick?

**`MLDSA65` unless you have a reason not to.** It is a finalised NIST standard; Falcon is still a draft.

**`Falcon512` when size matters.** Its signatures are roughly a fifth of ML-DSA-65's, and size is not a cosmetic concern here: every signature is broadcast to every node on the network and then stored for the life of the ledger. On a high-volume stream that difference compounds.

Two practical notes:

- **A key's type is permanent.** It is written into the identity's ledger metadata at onboard and every later transaction is verified against it. Moving an identity to a different scheme means onboarding a new identity.
- **Falcon-512's signature length varies** between 649 and 662 bytes, because its encoding compresses. Do not size buffers or database columns on a fixed width.

Both schemes come from [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) - pure JavaScript, no native dependency - so the same code runs in Node, in a browser and under React Native. A post-quantum key generated in a browser verifies in Node and on the ledger, which `npm test` checks on every run.

### Signing something that isn't a transaction

An exchange order, an attestation, an auth challenge - anything you need
signed by an identity but not submitted as a transaction:

```typescript
import { KeyHandler, PayloadHandler, KeyType } from "@activeledger/sdk-node";
// (or "@activeledger/sdk-web" - same class, same shape)

const payload = new PayloadHandler();
const key = await new KeyHandler().generateKey("maker", false, KeyType.MLDSA65);

const order = { pair: "VNR/USDT", side: "sell", amount: "100" };
const signature = payload.sign(order, key);

// Verifying happens somewhere else, usually with only the public key and
// scheme - off a ledger authority, say - and no private key at all.
payload.verify(order, signature, key.key.pub.pkcs8pem, key.type); // true
```

**Store `payload.canonical(order)` next to the signature and verify that.**
It returns the exact string being signed, and `JSON.stringify` is key-order
sensitive:

```typescript
payload.canonical({ pair: "VNR/USDT", side: "sell" }); // {"pair":"VNR/USDT","side":"sell"}
payload.canonical({ side: "sell", pair: "VNR/USDT" }); // {"side":"sell","pair":"VNR/USDT"}
```

Same fields, different bytes, and the signature won't verify. That's safe
while a payload round-trips as JSON, because key order survives - and stops
being safe the moment anything rebuilds the object field by field first: a
normaliser, a defaulter filling in optional fields, an ORM, a DTO mapper. The
failure then looks like a bad signature rather than an encoding problem.

### Requirements

Post-quantum support needs **Node 20.19 or later** (`@noble/post-quantum` is ESM-only, and `require(esm)` was unflagged there). These packages deliberately declare no `engines` floor - forcing a Node version onto your application is not something a client library should do - and CI runs the full suite against Node 20.19, 22 and 24 so that this stays true rather than merely claimed. Browsers and React Native are unaffected.

Your **ledger nodes** must be on **Activeledger 4.7.0 or later** to verify post-quantum signatures. Onboarding a post-quantum identity against an older node will be rejected.

### v2.1.0 - post-quantum keys

Additive; nothing breaks. `ICryptoProvider`'s `generate`/`sign`/`verify` gained an optional `type` defaulting to secp256k1, and `generateKey()` takes the type as its third argument so existing positional calls are unaffected. See [Post-quantum keys](#post-quantum-keys) above.

### v2.0.0 - breaking change from the old `@activeledger/sdk` package

This replaces the single `@activeledger/sdk` package (Node-only, depended on `@activeledger/activecrypto` + `node-rsa`) with the split above. What changed:

- **RSA support was dropped.** The ledger accepts secp256k1 identities everywhere RSA was previously used, so both packages only implement one curve. `KeyType.RSA` no longer exists; `generateKey(name, compressed?)` no longer takes a `KeyType` argument.
- **The optional transport-encryption feature is gone** (`Connection`'s `encrypt` flag, and `IKey`'s RSA-based request-body encryption). It was RSA-only and opt-in/off by default; it can come back later via WebCrypto's native RSA-OAEP if ever needed.
- **File-based key export/import (`exportKey`/`importKey`) is Node-only**, on `@activeledger/sdk-node`'s `KeyHandler`. `@activeledger/sdk-web`'s `KeyHandler` only generates/onboards - persisting a key is left to the app (localStorage, AsyncStorage, SecureStore, etc. all differ per environment).
- **`LedgerEvents` (SSE subscriptions) needs a polyfilled `EventSource` global in React Native.** Every browser has one natively; Node's build uses the `eventsource` npm package; React Native needs an app-level polyfill (e.g. `react-native-sse`) for `@activeledger/sdk-web` to work there.

### GitHub

[Repository here](https://github.com/activeledger/SDK-JS/)

## Installation

```
$ npm i -s @activeledger/sdk-node       # Node.js apps
$ npm i -s @activeledger/sdk-web        # Browser / React Native apps
```

## Usage

```typescript
import { KeyHandler, TransactionHandler, Connection } from "@activeledger/sdk-node";
// (or "@activeledger/sdk-web" - identical API)

const connection = new Connection("http", "localhost", 5260);
const keys = new KeyHandler();

const key = await keys.generateKey("mykey");
await keys.onboardKey(key, connection); // key.identity is now set

const tx = await new TransactionHandler().labelledTransaction(
  key,
  "default",
  "mycontract",
  "input",
  { amount: 1 },
  "stream-id",
);

const response = await connection.sendTransaction(tx);
```

### BIP-39 recovery phrases

Both packages can generate/restore a key from a 12-word recovery phrase:

```typescript
const key = await keys.generateBIP39Key("mykey"); // key.phrase is the 12 words
const restored = await keys.restoreBIP39Key("mykey", key.phrase);
```

By default this uses standard BIP-39 (mnemonic -> PBKDF2 seed) followed by just the BIP-32 **master-key** step (`HMAC-SHA512("Bitcoin seed", seed)`, first 32 bytes) - deliberately not any further hierarchical (HD) child derivation, since Activeledger attaches many independent keys to an identity rather than deriving them from one tree. A phrase generated on one package restores to the identical key on the other.

An optional BIP-39 passphrase is supported: `generateBIP39Key("mykey", { passphrase: "..." })`.

`{ legacy: true }` instead reproduces the original (now superseded) `@activeledger/sdk-bip39` package's scheme - `SHA256(phrase)` used directly as the private key, with no KDF or domain separation - **only** for recovering a phrase that was already generated by that package. It is meaningfully weaker (no purpose-built key-stretching, no domain separation from other uses of SHA-256) and should never be used for new keys.

### Seeds

A key can also be derived from the algorithm's own seed, with no phrase and no KDF:

```typescript
import { KeyType } from "@activeledger/sdk-core";

const key = await keys.generateKeyFromSeed("mykey", seed, true, KeyType.MLDSA65);
```

Seed lengths are fixed and a wrong one is **refused, not padded** — 32 bytes for `secp256k1` and `ml-dsa-65`, 48 for `falcon-512`.

This is how a private key moves between Activeledger SDKs. The PHP SDK's `ml-dsa-65` private key **is** a 32-byte seed, because `paragonie/pqcrypto_compat` implements FIPS 204 key generation from a seed but not `skEncode`/`skDecode` — so the 4032-byte encoding this SDK exports cannot be loaded there at all. A seed is the one form every SDK agrees on, and the same bytes give the same identity in all of them.

For `secp256k1` the seed **is** the private scalar, so it has to be a valid one. A seed of zero, or one at or above the curve order, is refused rather than reduced mod *n* — reducing produces a perfectly functional key belonging to a different identity, and nothing downstream ever reports a problem.

### Recovery phrases for post-quantum keys

`restoreBIP39Key` takes a `type`, so one phrase can back a `secp256k1`, an `ml-dsa-65` and a `falcon-512` identity at once:

```typescript
const pq = await keys.restoreBIP39Key("mykey", phrase, { type: KeyType.MLDSA65 });
```

Each type derives its own seed, so none of them reveals the others:

| Type | Seed derived from the BIP-39 seed `S` |
| --- | --- |
| `secp256k1` | `HMAC-SHA512("Bitcoin seed", S)[0..32]` |
| `ml-dsa-65` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)` |
| `falcon-512` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)` |

**`secp256k1` deliberately does not use HKDF.** Both packages have shipped that derivation since before the post-quantum types existed, so phrases are already in use; moving it onto HKDF would hand every one of those users a different key for a phrase that used to work — not an error, just an identity that is no longer theirs. The post-quantum types are new and carry no such debt, so they get the construction with proper domain separation.

`{ legacy: true }` is refused for a post-quantum type rather than ignored, since silently ignoring it would return a modern-derivation key to a caller who believed they were recovering an old one.

The full derivation, both layers, and the cross-language vectors are published in [`vectors/seed-vectors.json`](vectors/seed-vectors.json).

> [!IMPORTANT]
> **`activeledger-seed-v1` is not the only phrase derivation in use.** Varnir's chain-client ships its own — live since Activeledger 4.7.0 — and it differs for every key type: `HKDF-SHA256` with `varnir/pq-keygen/v1:<type>` for the post-quantum schemes, and a BIP-32 child at `m/44'/1'/0'/0/0` for `secp256k1` rather than the master key.
>
> Both start from the same BIP-39 seed, so the same twelve words give a **different identity** under each, with no error anywhere. Do not "unify" them: identities exist on both sides whose only backup is a phrase.
>
> You do not need to implement anyone else's scheme to interoperate. `generateKeyFromSeed` takes the algorithm's seed, so any derivation can be done by the caller and handed in — verified to reproduce a Varnir key exactly.

### Enums

| Key            | Ref                     | Notes                                |
| -------------- | ----------------------- | ------------------------------------ |
| Elliptic Curve | `KeyType.EllipticCurve` | secp256k1 - the default              |
| ML-DSA-65      | `KeyType.MLDSA65`       | Post-quantum, FIPS 204               |
| Falcon-512     | `KeyType.Falcon512`     | Post-quantum, smaller signatures     |

`POST_QUANTUM_KEY_TYPES` is also exported, for code that needs to branch on whether a key type is post-quantum.

### Interfaces

| Interface              | Description                                              |
| ----------------------- | ---------------------------------------------------------- |
| `IKey`                  | An Activeledger key (name, type, keypair, identity)        |
| `IOnboardTx`            | A key-onboarding transaction, mainly used internally        |
| `ILedgerResponse`       | A helper for the ledger response                            |
| `ICryptoProvider`       | The signing interface each platform package implements     |
| `IKeyExportOptions`     | (`sdk-node` only) File export options                       |
| `IKeyExtended`          | `IKey` plus the BIP-39 recovery `phrase`                    |
| `IBIP39Options`         | Options for `generateBIP39Key`/`restoreBIP39Key`             |

### Classes

| Class                | Description                                              |
| ---------------------- | ---------------------------------------------------------- |
| `Connection`           | Handles connecting to and posting transactions to a node    |
| `KeyHandler`           | Key generation and onboarding                               |
| `PayloadHandler`       | Signing and verifying arbitrary payloads (not transactions) |
| `TransactionHandler`   | Transaction building and signing                             |
| `LedgerEvents`         | SSE subscriptions to ActiveCore's events API                 |

## Development

This is an npm workspaces monorepo. Versioning and publishing use `scripts/set-version.mjs` plus `npm publish --workspaces` - see `.github/workflows/publish.yml`.

```
$ npm install
$ npm run build   # builds core, then node, then web, in that order
$ npm test        # build, then Jest unit tests for all three packages
$ node scripts/verify-interop.mjs         # cross-package signature compatibility check (secp256k1)
$ node scripts/verify-pq-interop.mjs      # the same for post-quantum keys, against the BUILT packages
$ node scripts/verify-ledger-interop.mjs  # compatibility check against the real ledger crypto (run from a checkout with the main activeledger repo built alongside)
$ node scripts/verify-bip39.mjs           # BIP-39: cross-package parity + backward compat with the old sdk-bip39 package (needs a sibling ../SDK-NodeJS-BIP39 checkout)
```

`sdk-core` and `sdk-node` share `jestconfig.json` at the repo root (plain CommonJS). That config transforms `@noble/*` into CommonJS rather than trying to `require()` it, and targets es2022 while doing so - at the repo's es2019 target, `@noble/post-quantum` transpiles into something that throws inside its own `_crystals` module. `sdk-web` has its own `packages/web/jest.config.mjs` and `test` script instead, since its `@noble/curves`/`@scure/bip39` dependencies are ESM-only and can't be `require()`'d from a CommonJS Jest run - it's run separately via `NODE_OPTIONS=--experimental-vm-modules jest --config jest.config.mjs` (Jest's documented mechanism for native ESM support), both invoked automatically by the root `npm test`. Cross-package interop (node<->web signature compatibility for both secp256k1 and post-quantum, compatibility with the real ledger crypto, BIP-39 backward compatibility with the old add-on) is deliberately left to the four scripts above rather than folded into either package's own Jest suite, since those checks are inherently about two separately-built packages (and in two cases, a second repo) talking to each other - not something either package's isolated unit tests are the right place for.

The post-quantum interop script in particular runs against the **built** packages rather than through Jest, because that is what consumers install - and because Jest's ESM runtime cannot load `sdk-node`'s CommonJS build at all, since it `require()`s an ESM-only dependency (something Node itself has done fine since 20.19). Testing what ships beat contorting the test runner into loading something else.

CI (`.github/workflows/tests.yml`) runs the whole of `npm test` on Node 20.19, 22 and 24 for every push and pull request.
