# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0]

### Changed

- **`restoreBIP39Key` now validates the recovery phrase** — wordlist and checksum — and throws if it does not pass. It never did before, and it was the only Activeledger SDK of seven that did not; the other six route their phrase entry point through a validating `toSeed`.

  This is a correctness fix, and it fails in the direction that matters. An unchecked phrase does not fail loudly: a typo derives a different **valid** key for an identity nobody owns, and the only symptom is the ledger not recognising it, a long way from the cause.

- **If you relied on deriving from a string that is not a BIP-39 mnemonic, pass `{ validate: false }`.** The behaviour is unchanged under that flag, and the thrown message names it. The opt-out exists because refusing a phrase that used to work would make that identity unrecoverable — the same failure validation prevents, pointed the other way.

- `{ legacy: true }` is never validated. It is `SHA256(phrase)` and was never a BIP-39 mnemonic operation, and the original `@activeledger/sdk-bip39` package never consulted the wordlist.

### Fixed

- The two packages were not equally lenient, which this resolves for the default path. `@scure/bip39` enforces the word count inside `mnemonicToSeedSync` while node's `bip39` enforces nothing, so `restoreBIP39Key("some arbitrary string")` used to derive a key on `sdk-node` and throw on `sdk-web`. Both now validate, so both agree; the difference is only reachable via `{ validate: false }`.

## [2.3.0]

### Added

- `recovery` — the seed derivation as a public module in both packages, exporting `toSeed`, `deriveSeed`, `deriveBIP32MasterKey`, `validate` and `seedSize`. This was the only SDK of the seven where a caller could not reach the derivation without reimplementing it, which is how a second, drifting copy of a KDF gets written.

  ```ts
  import { recovery } from "@activeledger/sdk-node";
  const seed = recovery.deriveSeed(KeyType.Falcon512, recovery.toSeed(phrase));
  ```

  `falcon-512`'s seed derives even where Falcon itself is unavailable, so a phrase here can produce the seed for an identity used elsewhere.

- `toSeed` validates the phrase by default — wordlist and checksum — matching the other six SDKs.

### Changed

- `restoreBIP39Key` now shares one derivation with the `recovery` module rather than holding a private copy in each platform package. No derived value changes; the published vectors are checked against the live method on every test run.

### Notes

- `restoreBIP39Key` still does **not** validate the phrase, deliberately. Neither `bip39` nor `@scure/bip39` validates inside `mnemonicToSeedSync`, so this SDK has always accepted an arbitrary string; rejecting one now would make an existing identity unrecoverable.

- The two platforms are not equally lenient and this predates the module: `@scure/bip39` enforces the word count, node's `bip39` enforces nothing, so `restoreBIP39Key("some arbitrary string")` derives a key on `sdk-node` and throws on `sdk-web`. `toSeed`'s default validation is the only way to get the same answer on both.

## [2.2.0]

### Added

- `PayloadHandler` - signing and verifying arbitrary payloads (an exchange order, an attestation, an auth challenge) rather than transactions. Same class name and shape in `@activeledger/sdk-node` and `@activeledger/sdk-web`.

  ```ts
  const payload = new PayloadHandler();
  const signature = payload.sign(order, key);
  payload.verify(order, signature, publicKey, type);
  ```

  This was possible before by instantiating the platform's crypto provider directly, and those are public. What it was not was portable: every other class in this SDK is named the same in both packages, but the providers are `NodeCryptoProvider` and `WebCryptoProvider`, so a client shared between a server and a browser could not sign a payload with one piece of code.

- `PayloadHandler.canonical(payload)` returns the exact string that gets signed, so an application can store it alongside the signature and verify that rather than re-deriving it. `JSON.stringify` is key-order sensitive, so a payload rebuilt field by field before verification - by a normaliser, a defaulter, an ORM, a DTO mapper - produces different bytes and a signature that will not verify, presenting as a bad signature rather than an encoding problem. Verifying the stored string is immune to it.

- `generateKeyFromSeed(name, seed, compressed?, type?)` - derive a key from the algorithm's own seed. No KDF: 32 bytes for `secp256k1` and `ml-dsa-65`, 48 for `falcon-512`, and a wrong length is refused rather than padded, because a padded seed is a different identity rather than a malformed one.

  This is how a private key moves between Activeledger SDKs. The PHP SDK's `ml-dsa-65` private key **is** a 32-byte seed - `paragonie/pqcrypto_compat` implements FIPS 204 key generation from a seed but not `skEncode`/`skDecode` - so the 4032-byte encoding this SDK exports cannot be loaded there at all. The seed can be, and gives an identical public key.

- `restoreBIP39Key` now takes a `type`, so one recovery phrase can back a `secp256k1`, an `ml-dsa-65` and a `falcon-512` identity at once. Each derives its own seed, so none of them reveals the others.

  | Type | Seed from the BIP-39 seed `S` |
  | --- | --- |
  | `secp256k1` | `HMAC-SHA512("Bitcoin seed", S)[0..32]` |
  | `ml-dsa-65` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)` |
  | `falcon-512` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)` |

- `vectors/seed-vectors.json` - the derivation published with cross-language vectors, including invalid seeds a port must refuse.

### Changed

- `restoreBIP39Key` for `secp256k1` is **unchanged**, deliberately. Both packages have shipped that derivation since before the post-quantum types existed, so phrases are already in use, and moving it onto HKDF would hand every one of those users a different key for a phrase that used to work - not an error, just an identity that is no longer theirs. `verify-seed-vectors.mjs` checks all 14 `secp256k1` vectors against the live `restoreBIP39Key`, so changing it fails the build rather than happening quietly.

- `{ legacy: true }` is now refused for a post-quantum type rather than silently ignored, since ignoring it would return a modern-derivation key to a caller who believed they were recovering an old one.

- `ICryptoProvider.generateFromSeed` is optional, so a provider written before this still satisfies the interface. Its absence is reported by name rather than as "not a function".

## [2.1.0]

### Added

- Post-quantum key types: **ML-DSA-65** (FIPS 204) and **Falcon-512** (FN-DSA), alongside secp256k1, in both `@activeledger/sdk-node` and `@activeledger/sdk-web`. Matches the support added to `@activeledger/activecrypto` in Activeledger 4.7.0, so a key generated by either SDK is one the ledger can verify.

  ```ts
  const key = await keyHandler.generateKey("my-key", false, KeyType.MLDSA65);
  ```

  ML-DSA-65 is the conservative choice, a finalised standard. Falcon-512 is still draft and earns its place on size — 649-662 byte signatures against ML-DSA-65's 3309 — which matters because every signature is broadcast to every node on the network and then stored for the life of the ledger.

- `POST_QUANTUM_KEY_TYPES` exported from `@activeledger/sdk-core`, for code that needs to branch on whether a key type is post-quantum.

- A cross-package interop check (`scripts/cross-package-pq.mjs`) run as part of `npm test`. A key generated in a browser has to verify on a server and on the ledger; if the two packages disagreed about encoding or entropy, every signature made on one side would be worthless on the other and neither package's own tests would notice.

- A CI workflow. The repository previously had a publish workflow and nothing that ran the tests, so no pull request was checked. It runs the full suite on Node 20.19, 22 and 24.

### Changed

- `ICryptoProvider.generate/sign/verify` take an **optional** `type` parameter, defaulting to secp256k1. An implementation written before this still satisfies the interface, and every existing call keeps working.

- `KeyHandler.generateKey()` takes the key type as its **third** argument, after `compressed`, so existing positional calls — `generateKey(name, true)` — keep meaning what they did. `compressed` is a secp256k1 concept and is ignored by the post-quantum schemes.

- `skipLibCheck` is now set. `@noble/post-quantum`'s own type declarations import with explicit `.ts` extensions, which this `moduleResolution` rejects; the alternative was changing how every import in every package resolves in order to type check a dependency we do not maintain.

### Notes

- **No `engines` floor is declared.** This is a client library, and forcing a Node version onto a consumer's application is a cost the ledger's own `>=24` requirement does not justify here. The real floor is Node **20.19**, where `require(esm)` was unflagged — `@noble/post-quantum` is ESM-only. CI runs against 20.19 so that claim stays checked rather than asserted.

- Entropy for post-quantum signing is supplied explicitly rather than left to `@noble`, which otherwise reads `globalThis.crypto.getRandomValues` — not something a library should assume is present and unmodified in someone else's process. `sdk-node` takes it from `node:crypto`, `sdk-web` from WebCrypto, which is also what makes this work under React Native where `randomBytes` does not exist.

- **Falcon-512's signature length varies**, between 649 and 662 bytes, because its encoding compresses — and `@noble` declares no signature length for it. Nothing here assumes a fixed width, and a test pins the distinction against ML-DSA-65's fixed 3309.

## [2.0.0] - Unreleased

### Changed

- **Breaking:** split the single `@activeledger/sdk` package into a monorepo of three packages - `@activeledger/sdk-core` (shared, internal), `@activeledger/sdk-node` (Node.js, signing via `node:crypto`), and `@activeledger/sdk-web` (browsers and React Native, signing via `@noble/curves`).
- **Breaking:** RSA support removed - both packages only support secp256k1 identities. `KeyType.RSA` no longer exists; `generateKey()` no longer takes a `KeyType` argument.
- **Breaking:** `Connection`'s optional RSA-based transport-encryption feature removed.
- **Breaking:** `exportKey`/`importKey` (file-based key persistence) moved to `@activeledger/sdk-node`'s `KeyHandler` only - not available on `@activeledger/sdk-web`.
- `@activeledger/sdk-node` no longer depends on `@activeledger/activecrypto` or `node-rsa` - secp256k1 signing is implemented directly on top of `node:crypto`.

### Added

- `KeyHandler.generateBIP39Key`/`restoreBIP39Key` on both `@activeledger/sdk-node` and `@activeledger/sdk-web` - standard BIP-39 seed + BIP-32 master-key derivation (no HD child derivation) by default, with a `legacy: true` option reproducing the original `@activeledger/sdk-bip39` package's `SHA256(phrase)` scheme for backward compatibility with existing phrases.

## [1.3.6] - 02-02-2023

### Fixed

- Dependency issues (Axios)


## [1.3.5] - 02-02-2023

### Fixed

- Updated definitations to include $responses and $debug

## [1.3.4] - 21-02-2020

### Fixed

- Eventsource reference for node builds

## [1.3.3] - 12-09-2019

### Fixed

- Uses native EventSource is available else uses polyfill

## [1.3.2] - 30-12-2019

### Fixed

- Event emitter being unsubscribed to soon

## [1.3.1] - 12-09-2019

### Changed

- Updated some packages
- Corrected labelled transaction test

### Fixed

- Import reject message if file not found was the same as the export error message when a file cannot be written
- Activedefintions error if not installed, moved to dependencies until solution is found

## [1.3.0] - 09-09-2019

### Added

- Server sent event handling

## [1.2.5] - 22-05-2019

### Added

- This changelog
- Added labelled transaction builder function, with interface
- Browser check before running code reliant on fs

### Changed

- Test updates
- Refactored code

### Removed

## [1.2.1] - 21-11-2018

### Changed

- Fixed issue with Readme
- Updated tests
- Updated to work with Activecrypto changes
- Updated Readme
- Sign Transaction function now accepts a string

## [1.2.0] - 07-11-2018

### Added

- Keys can be imported and exported

### Changed

- Using TypeDoc for documentation
- Test updates

### Fixed

- GitHub IO display

## [1.1.1] - 05-11-2018

### Added

- Encryption test

### Fixed

- Removed erroneous JSON.parse

## [1.1.0] - 31-10-2018

### Changed

- Switched to Axios for http requests to improve browser support

## [1.0.0] - 30-10-2018

### Initial release

- Activeledger Node.js SDK
- Key handling
- Connection handling
- Transaction handling
- Readme
