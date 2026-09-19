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

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ICryptoProvider, IKeyHandleDetails, IKeyHandler } from "@activeledger/sdk-core";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { falcon512 } from "@noble/post-quantum/falcon.js";

const textEncoder = new TextEncoder();

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Hand-rolled base64, deliberately not using btoa/atob - those are DOM
// globals available in every browser but NOT in React Native's JS engine
// (Hermes) without a polyfill, and this SDK has no other reason to require
// one.
const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function toBase64(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;

    result += BASE64_CHARS[b0 >> 2];
    result += BASE64_CHARS[((b0 & 0x03) << 4) | (b1 === undefined ? 0 : b1 >> 4)];
    result += b1 === undefined ? "=" : BASE64_CHARS[((b1 & 0x0f) << 2) | (b2 === undefined ? 0 : b2 >> 6)];
    result += b2 === undefined ? "=" : BASE64_CHARS[b2 & 0x3f];
  }
  return result;
}

function fromBase64(b64: string): Uint8Array {
  const clean = b64.replace(/=+$/, "");
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const char of clean) {
    const value = BASE64_CHARS.indexOf(char);
    if (value === -1) continue;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }

  return new Uint8Array(bytes);
}

/**
 * ICryptoProvider backed by @noble/curves (audited, pure JS, zero
 * dependencies) - browsers have no native WebCrypto support for secp256k1
 * (only the NIST curves), and neither does React Native's JS engine, so
 * this is the closest thing to "native" available across both.
 *
 * Produces SHA-256 + DER ECDSA signatures, matching what the ledger itself
 * produces/expects and what @activeledger/sdk-node's node:crypto-based
 * provider produces, so signatures from either package verify identically
 * against the ledger (and against each other).
 *
 * @export
 * @class WebCryptoProvider
 */
/**
 * The post-quantum schemes, keyed by the type string that travels with the
 * transaction and is stored on the ledger as meta.authorities[].type.
 *
 * Deliberately the same table, encoding and entropy handling in both
 * platform packages: a key generated in a browser has to verify in a node,
 * and the ledger has to verify both. Keys are base64 rather than the "0x"
 * hex secp256k1 uses here - they are 897 to 4032 bytes, where hex would cost
 * a third more for no benefit.
 */
const POST_QUANTUM: {
  [type: string]: {
    keygen: (seed: Uint8Array) => { publicKey: Uint8Array; secretKey: Uint8Array };
    sign: (
      msg: Uint8Array,
      secretKey: Uint8Array,
      opts?: { extraEntropy?: Uint8Array | false }
    ) => Uint8Array;
    verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean;
    // No `signature` length here on purpose: ML-DSA's is fixed at 3309 bytes
    // but Falcon's varies (649-662), and noble does not declare one for it.
    lengths: { publicKey: number; secretKey: number; seed: number };
  };
} = {
  "ml-dsa-65": ml_dsa65 as never,
  "falcon-512": falcon512 as never,
};

export class WebCryptoProvider implements ICryptoProvider {
  public generate(compressed?: boolean, type?: string): IKeyHandler {
    const pq = type ? POST_QUANTUM[type] : undefined;
    if (pq) {
      const seed = new Uint8Array(pq.lengths.seed);
      // WebCrypto rather than node:crypto - this package targets browsers and
      // React Native, where randomBytes does not exist.
      crypto.getRandomValues(seed);
      const keys = pq.keygen(seed);
      return {
        prv: { pkcs8pem: toBase64(keys.secretKey) },
        pub: { pkcs8pem: toBase64(keys.publicKey) },
      };
    }

    const secretKey = secp256k1.utils.randomSecretKey();
    const publicKey = secp256k1.getPublicKey(secretKey, compressed ? true : false);

    return {
      prv: { pkcs8pem: "0x" + toHex(secretKey) },
      pub: { pkcs8pem: "0x" + toHex(publicKey) },
    };
  }

  /**
   * Derive a key pair from the algorithm's own seed. No KDF, no phrase - the
   * bytes given are the seed the scheme itself takes.
   *
   * Byte-for-byte identical to sdk-node's, which is the point: a seed is the
   * one private-key form every Activeledger SDK can agree on, including PHP,
   * whose ml-dsa-65 private key IS a 32-byte seed.
   */
  public generateFromSeed(seed: Uint8Array, compressed?: boolean, type?: string): IKeyHandler {
    const pq = type ? POST_QUANTUM[type] : undefined;

    if (pq) {
      // Refused rather than padded. A seed of the wrong length is a
      // different identity, not a malformed one.
      if (seed.length !== pq.lengths.seed) {
        throw new Error(`${type} needs a ${pq.lengths.seed}-byte seed, got ${seed.length}`);
      }

      const keys = pq.keygen(seed);
      return {
        prv: { pkcs8pem: toBase64(keys.secretKey) },
        pub: { pkcs8pem: toBase64(keys.publicKey) },
      };
    }

    if (seed.length !== 32) {
      throw new Error(`secp256k1 needs a 32-byte seed, got ${seed.length}`);
    }

    // @noble/curves refuses a scalar outside [1, n-1] rather than reducing
    // it, which is the behaviour wanted here - a reduced scalar is a working
    // key for someone else's identity. Re-thrown with the seed named, since
    // noble's own message does not mention where the bytes came from.
    let publicKey: Uint8Array;
    try {
      publicKey = secp256k1.getPublicKey(seed, compressed ? true : false);
    } catch {
      throw new Error(
        "seed is not a valid secp256k1 private key - the scalar must be in [1, n-1]",
      );
    }

    return {
      prv: { pkcs8pem: "0x" + toHex(seed) },
      pub: { pkcs8pem: "0x" + toHex(publicKey) },
    };
  }

  public sign(data: string, prv: IKeyHandleDetails, type?: string): string {
    const pq = type ? POST_QUANTUM[type] : undefined;
    if (pq) {
      const entropy = new Uint8Array(pq.lengths.seed);
      crypto.getRandomValues(entropy);
      return toBase64(
        pq.sign(textEncoder.encode(data), fromBase64(prv.pkcs8pem), {
          extraEntropy: entropy,
        })
      );
    }

    const message = textEncoder.encode(data);
    const secretKey = fromHex(prv.pkcs8pem);
    const signature = secp256k1.sign(message, secretKey, { format: "der" });
    return toBase64(signature as Uint8Array);
  }

  public verify(data: string, signature: string, pub: IKeyHandleDetails, type?: string): boolean {
    const pq = type ? POST_QUANTUM[type] : undefined;
    if (pq) {
      try {
        return pq.verify(
          fromBase64(signature),
          textEncoder.encode(data),
          fromBase64(pub.pkcs8pem)
        );
      } catch {
        return false;
      }
    }

    const message = textEncoder.encode(data);
    const publicKey = fromHex(pub.pkcs8pem);
    const sig = fromBase64(signature);
    // lowS: false - node:crypto's Sign stream (used by @activeledger/sdk-node
    // and by the ledger itself) doesn't normalize signatures to the low-S
    // half-order the way @noble/curves' sign() does by default, and OpenSSL's
    // verify doesn't require it either. @noble/curves' verify() REJECTS
    // high-S signatures unless told not to - without this, roughly half of
    // all otherwise-valid node/ledger signatures would fail here.
    return secp256k1.verify(sig, message, publicKey, { format: "der", lowS: false });
  }
}
