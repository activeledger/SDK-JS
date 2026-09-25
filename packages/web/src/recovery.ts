/*
 * MIT License (MIT)
 * Copyright (c) 2019 Activeledger
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { KeyType } from "@activeledger/sdk-core";

const textEncoder = new TextEncoder();

/**
 * BIP-39 recovery phrases, and the seed each key type derives from one.
 *
 * Exported so a caller can take the derivation without the key generation -
 * to derive a `falcon-512` seed for an SDK that can use it, to inspect the
 * intermediate when a recovered identity is not the expected one, or to feed
 * the seed to `generateKeyFromSeed` directly. The same module exists in every
 * other Activeledger SDK; this one was the last to expose it.
 *
 * ## The derivation
 *
 * ```text
 * BIP-39 seed S = PBKDF2-HMAC-SHA512(phrase, "mnemonic" + passphrase, 2048, 64)
 *
 * ml-dsa-65   HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)
 * falcon-512  HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)
 * secp256k1   HMAC-SHA512("Bitcoin seed", S)[0..32]
 * ```
 *
 * `secp256k1` does not use HKDF, and that is not an oversight: this SDK
 * shipped that derivation before the post-quantum types existed, so phrases
 * are already in use and changing it would hand those users a different key
 * for a phrase that used to work.
 *
 * Published, with cross-language vectors, in `vectors/seed-vectors.json`.
 */

/** A BIP-39 seed is always 64 bytes. */
export const BIP39_SEED_BYTES = 64;

/**
 * Each algorithm's own seed length.
 *
 * A wrong length is refused rather than padded: a padded seed is a different
 * identity, not a malformed one.
 */
export const SEED_SIZES: Readonly<Record<string, number>> = Object.freeze({
  [KeyType.EllipticCurve]: 32,
  [KeyType.MLDSA65]: 32,
  [KeyType.Falcon512]: 48,
});

/** The seed length the given key type takes. */
export function seedSize(type: KeyType): number {
  const size = SEED_SIZES[type];
  if (!size) {
    throw new Error(`${type} keys cannot be derived from a seed`);
  }
  return size;
}

/**
 * Checks a phrase, returning it normalised and single-spaced.
 *
 * Both the wordlist and the checksum. A mistyped phrase that is not checked
 * does not fail: it derives a perfectly valid key for an identity nobody
 * owns, and the only symptom is the ledger not recognising it.
 *
 * NOTE that `KeyHandler.restoreBIP39Key` deliberately does NOT call this.
 * Neither `bip39` nor `@scure/bip39` validates inside `mnemonicToSeedSync`,
 * so this SDK has always accepted an arbitrary string there and derived a key
 * from it. Someone may be relying on that, and rejecting their phrase now
 * would make an existing identity unrecoverable - the same failure this
 * function exists to prevent. Call it explicitly, or use `toSeed`.
 *
 * @throws if the phrase is not a valid mnemonic
 */
export function validate(phrase: string): string {
  const words = phrase.normalize("NFKD").split(/\s+/).filter(Boolean);

  // 12, 15, 18, 21 and 24 are the only valid lengths.
  if (words.length < 12 || words.length > 24 || words.length % 3 !== 0) {
    throw new Error(`a BIP-39 phrase is 12, 15, 18, 21 or 24 words, got ${words.length}`);
  }

  // Checked before the checksum so the error names the offending word rather
  // than blaming the checksum for a typo the caller can see.
  words.forEach((word, index) => {
    if (!wordlist.includes(word)) {
      throw new Error(`word ${index + 1} ("${word}") is not in the BIP-39 English wordlist`);
    }
  });

  const normalised = words.join(" ");
  if (!validateMnemonic(normalised, wordlist)) {
    throw new Error(
      "the BIP-39 checksum does not match - the phrase has a typo or the words are in the " +
        "wrong order. Deriving from it anyway would produce a valid key for an identity " +
        "nobody owns. If you meant to derive from a non-mnemonic string, pass " +
        "{ validate: false }.",
    );
  }

  return normalised;
}

/**
 * Turns a recovery phrase into its 64-byte BIP-39 seed.
 *
 * Validates by default, matching every other Activeledger SDK. Pass
 * `{ validate: false }` for the lenient behaviour `restoreBIP39Key` has
 * always had.
 */
export function toSeed(
  phrase: string,
  passphrase = "",
  options: { validate?: boolean } = {},
): Uint8Array {
  const checked = options.validate === false ? phrase : validate(phrase);
  return mnemonicToSeedSync(checked, passphrase);
}

/**
 * Turns a BIP-39 seed into the seed the given key type takes.
 *
 * Hand the result to `KeyHandler.generateKeyFromSeed`, or to another SDK -
 * `falcon-512`'s seed derives here even where Falcon itself is unavailable.
 */
export function deriveSeed(type: KeyType, bip39Seed: Uint8Array): Uint8Array {
  if (bip39Seed.length !== BIP39_SEED_BYTES) {
    throw new Error(`a BIP-39 seed is ${BIP39_SEED_BYTES} bytes, got ${bip39Seed.length}`);
  }

  if (type === KeyType.EllipticCurve) {
    return deriveBIP32MasterKey(bip39Seed);
  }

  // An empty salt means a block of zero bytes of the hash length, which is
  // what RFC 5869 specifies. An omitted salt gives the same PRK - HMAC pads a
  // short key to the block size, and a zero-length key pads to that same
  // all-zero block - so a port passing neither is still correct.
  return hkdf(
    sha512,
    bip39Seed,
    new Uint8Array(0),
    textEncoder.encode(`activeledger-seed-v1:${type}`),
    seedSize(type),
  );
}

/**
 * BIP-32's master key generation step, applied to a BIP-39 seed - and nothing
 * past that root, since no child paths are derived here.
 *
 * Exported because it is the whole of the `secp256k1` derivation, and a
 * caller comparing against another implementation needs to see this step
 * rather than infer it. Another client in the wild derives a BIP-32 CHILD at
 * `m/44'/1'/0'/0/0` instead, which is a different identity from the same
 * phrase.
 */
export function deriveBIP32MasterKey(bip39Seed: Uint8Array): Uint8Array {
  return hmac(sha512, textEncoder.encode("Bitcoin seed"), bip39Seed).subarray(0, 32);
}
