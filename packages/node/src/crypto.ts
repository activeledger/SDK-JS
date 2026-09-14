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
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { falcon512 } from "@noble/post-quantum/falcon.js";

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

export class NodeCryptoProvider implements ICryptoProvider {
  public generate(compressed?: boolean, type?: string): IKeyHandler {
    const pq = type ? POST_QUANTUM[type] : undefined;
    if (pq) {
      const keys = pq.keygen(new Uint8Array(crypto.randomBytes(pq.lengths.seed)));
      return {
        prv: { pkcs8pem: Buffer.from(keys.secretKey).toString("base64") },
        pub: { pkcs8pem: Buffer.from(keys.publicKey).toString("base64") },
      };
    }

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

  public sign(data: string, prv: IKeyHandleDetails, type?: string): string {
    const pq = type ? POST_QUANTUM[type] : undefined;
    if (pq) {
      // Entropy supplied rather than left to noble, which otherwise reads
      // globalThis.crypto.getRandomValues - not something a library should
      // depend on being present and unmodified in someone else's process.
      return Buffer.from(
        pq.sign(
          new Uint8Array(Buffer.from(data, "utf8")),
          new Uint8Array(Buffer.from(prv.pkcs8pem, "base64")),
          { extraEntropy: new Uint8Array(crypto.randomBytes(pq.lengths.seed)) }
        )
      ).toString("base64");
    }

    const sign = crypto.createSign("sha256");
    sign.update(data);
    return Buffer.from(sign.sign(this.toPrivatePem(prv.pkcs8pem), "hex"), "hex").toString("base64");
  }

  public verify(data: string, signature: string, pub: IKeyHandleDetails, type?: string): boolean {
    const pq = type ? POST_QUANTUM[type] : undefined;
    if (pq) {
      // Never throws: a malformed signature and a wrong one mean the same
      // thing to a caller.
      try {
        return pq.verify(
          new Uint8Array(Buffer.from(signature, "base64")),
          new Uint8Array(Buffer.from(data, "utf8")),
          new Uint8Array(Buffer.from(pub.pkcs8pem, "base64"))
        );
      } catch {
        return false;
      }
    }

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
