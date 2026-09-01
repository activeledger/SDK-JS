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

import * as crypto from "crypto";
import { ICryptoProvider, IKeyHandleDetails, IKeyHandler } from "@activeledger/sdk-core";
import { AsnParser } from "./asn";

/**
 * ICryptoProvider backed entirely by node:crypto's native (OpenSSL) secp256k1
 * support - no external crypto dependency. Signatures are SHA-256 + DER
 * ECDSA, matching what the ledger itself produces/expects
 * (packages/crypto/src/crypto/keypair.ts in the main activeledger repo) and
 * what @activeledger/sdk-web's @noble/curves-based provider produces, so
 * signatures from either package verify identically against the ledger.
 *
 * @export
 * @class NodeCryptoProvider
 */
export class NodeCryptoProvider implements ICryptoProvider {
  public generate(compressed?: boolean): IKeyHandler {
    const curve = crypto.createECDH("secp256k1");
    curve.generateKeys();

    return {
      // ECDH.getPrivateKey() strips leading zero bytes instead of returning
      // a fixed-width 32-byte scalar (about 1 in 256 keys per leading zero
      // byte - roughly 1 in 400 overall) - left-pad back to 32 bytes, or a
      // short-by-chance key silently produces a private hex string other
      // implementations (including @noble/curves and this SDK's own PEM
      // encoding) don't agree with node:crypto about how to interpret.
      prv: { pkcs8pem: "0x" + this.toFixedLength(curve.getPrivateKey(), 32).toString("hex") },
      pub: {
        pkcs8pem: compressed
          ? "0x" + curve.getPublicKey("hex", "compressed")
          : "0x" + curve.getPublicKey("hex", "uncompressed"),
      },
    };
  }

  /**
   * Left-pad a big-endian scalar to a fixed byte length.
   *
   * @private
   */
  private toFixedLength(buf: Buffer, length: number): Buffer {
    if (buf.length === length) {
      return buf;
    }
    const padded = Buffer.alloc(length);
    buf.copy(padded, length - buf.length);
    return padded;
  }

  public sign(data: string, prv: IKeyHandleDetails): string {
    const sign = crypto.createSign("sha256");
    sign.update(data);
    return Buffer.from(sign.sign(this.toPrivatePem(prv.pkcs8pem), "hex"), "hex").toString("base64");
  }

  public verify(data: string, signature: string, pub: IKeyHandleDetails): boolean {
    const verify = crypto.createVerify("sha256");
    verify.update(data);
    return verify.verify(this.toPublicPem(pub.pkcs8pem), Buffer.from(signature, "base64"));
  }

  /**
   * node:crypto's Sign/Verify streams need SEC1/SPKI PEM, not the raw "0x"
   * hex this SDK stores keys as. The embedded public-key field in the SEC1
   * structure is left empty - OpenSSL doesn't need it to sign with the
   * private scalar, only to verify, and this exact approach is already
   * proven in production by the main activeledger repo's own KeyPair class.
   *
   * @private
   */
  private toPrivatePem(key: string): string {
    if (key.indexOf("PRIVATE") !== -1) {
      return key;
    }
    return AsnParser.encodeECPrivateKey(Buffer.from(key.replace(/^0x/, ""), "hex"), Buffer.from(""));
  }

  private toPublicPem(key: string): string {
    if (key.indexOf("PUBLIC") !== -1) {
      return key;
    }
    return AsnParser.encodeECPublicKey(Buffer.from(key.replace(/^0x/, ""), "hex"));
  }
}
