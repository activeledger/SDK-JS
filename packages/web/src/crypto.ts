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
export class WebCryptoProvider implements ICryptoProvider {
  public generate(compressed?: boolean): IKeyHandler {
    const secretKey = secp256k1.utils.randomSecretKey();
    const publicKey = secp256k1.getPublicKey(secretKey, compressed ? true : false);

    return {
      prv: { pkcs8pem: "0x" + toHex(secretKey) },
      pub: { pkcs8pem: "0x" + toHex(publicKey) },
    };
  }

  public sign(data: string, prv: IKeyHandleDetails): string {
    const message = textEncoder.encode(data);
    const secretKey = fromHex(prv.pkcs8pem);
    const signature = secp256k1.sign(message, secretKey, { format: "der" });
    return toBase64(signature as Uint8Array);
  }

  public verify(data: string, signature: string, pub: IKeyHandleDetails): boolean {
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
