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

// RSA support was dropped when this SDK split into node/web packages - the
// ledger accepts secp256k1 identities everywhere RSA was previously used, so
// every platform package only needs to implement one curve.
export enum KeyType {
  EllipticCurve = "secp256k1",
  /**
   * ML-DSA-65 (FIPS 204). The conservative post-quantum choice - a finalised
   * standard, at the cost of 1952 byte public keys and 3309 byte signatures
   * against secp256k1's 33 and ~71.
   */
  MLDSA65 = "ml-dsa-65",
  /**
   * Falcon-512 (FN-DSA). Still a draft standard, and roughly a fifth of
   * ML-DSA-65's signature size - which matters because every signature is
   * broadcast to every node and then stored for the life of the ledger.
   *
   * Its signature length VARIES, 649-662 bytes, because the encoding
   * compresses. Do not assume a fixed width anywhere.
   */
  Falcon512 = "falcon-512",
}

/** The post-quantum members of KeyType, for code that has to branch on it. */
export const POST_QUANTUM_KEY_TYPES: readonly KeyType[] = [
  KeyType.MLDSA65,
  KeyType.Falcon512,
];
