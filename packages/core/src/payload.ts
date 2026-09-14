/*
 * MIT License (MIT)
 * Copyright (c) 2026 Activeledger
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

import { ICryptoProvider, IKey } from "./interfaces";

/**
 * Signs and verifies arbitrary payloads - an exchange order, an attestation,
 * an auth challenge - as opposed to transactions, which TransactionHandler
 * covers.
 *
 * This was possible before, by instantiating the platform's crypto provider
 * directly. The problem was that it is the one thing in this SDK that could
 * not be written once: every other public class is named the same in
 * sdk-node and sdk-web, but the providers are NodeCryptoProvider and
 * WebCryptoProvider, so a chain-client shared between a server and a browser
 * could not sign a payload with the same code.
 *
 * It also left canonicalisation to the caller, which is the dangerous part -
 * see canonical().
 */
export class PayloadHandler {
  constructor(private crypto: ICryptoProvider) {}

  /**
   * The exact string that sign() and verify() operate on.
   *
   * Worth exposing, and worth using. An object is canonicalised with
   * JSON.stringify, which is **key-order sensitive**: the same fields in a
   * different insertion order produce different bytes and therefore a
   * signature that will not verify.
   *
   *   {"pair":"VNR/USDT","side":"sell"}   and
   *   {"side":"sell","pair":"VNR/USDT"}   do not match
   *
   * That is safe while a payload round-trips as JSON, because key order
   * survives. It stops being safe the moment anything rebuilds the object
   * field by field before verifying - a normaliser, a defaulter filling in
   * optional fields, an ORM, a DTO mapper. The failure then looks like a bad
   * signature rather than an encoding problem, which is a miserable thing to
   * debug.
   *
   * So: persist what this returns alongside the signature, and verify THAT,
   * rather than re-deriving it from an object you have rebuilt.
   *
   * @param payload - an object, or a string already canonicalised
   */
  public canonical(payload: unknown): string {
    return typeof payload === "string" ? payload : JSON.stringify(payload);
  }

  /**
   * Sign a payload with a key.
   *
   * The key carries its own scheme, so secp256k1 and the post-quantum
   * schemes are signed the same way from the caller's side.
   *
   * @param payload - an object, or a string from canonical()
   * @param key - the key to sign with; key.type selects the scheme
   */
  public sign(payload: unknown, key: IKey): string {
    return this.crypto.sign(this.canonical(payload), key.key.prv, key.type);
  }

  /**
   * Verify a payload against a public key.
   *
   * Takes the public key and scheme separately rather than an IKey, because
   * the caller verifying is usually not the caller who signed - an exchange
   * checking a maker's order has the authority's `public` and `type` off the
   * ledger, and no private key at all.
   *
   * Returns false rather than throwing on malformed input: a wrong signature
   * and an unparseable one mean the same thing to a caller.
   *
   * @param payload - an object, or the exact string that was signed
   * @param signature - base64, as sign() returned it
   * @param publicKey - the signer's public key
   * @param type - the signer's scheme; defaults to secp256k1
   */
  public verify(
    payload: unknown,
    signature: string,
    publicKey: string,
    type?: string
  ): boolean {
    try {
      return this.crypto.verify(
        this.canonical(payload),
        signature,
        { pkcs8pem: publicKey },
        type
      );
    } catch {
      return false;
    }
  }
}
