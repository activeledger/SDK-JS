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

    NodeCryptoProvider.requireSecp256k1(type);
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
   * Derive a key pair from the algorithm's own seed. No KDF, no phrase - the
   * bytes given are the seed the scheme itself takes.
   *
   * This is what makes a private key portable between SDKs. The PHP SDK's
   * ml-dsa-65 private key IS a 32-byte seed, because its library implements
   * FIPS 204 key generation from a seed but not skEncode/skDecode, so the
   * 4032-byte encoding this SDK exports cannot be loaded there at all. A
   * seed is the one form all of them agree on.
   *
   * For recovery-phrase derivation see KeyHandler.restoreBIP39Key, which
   * turns a phrase into the right seed for the requested type and then calls
   * this.
   */
  public generateFromSeed(seed: Uint8Array, compressed?: boolean, type?: string): IKeyHandler {
    const pq = type ? POST_QUANTUM[type] : undefined;

    if (pq) {
      // Refused rather than padded. A seed of the wrong length is a different
      // identity, and a library that accepts it returns a working key that
      // is not the one the caller asked for.
      if (seed.length !== pq.lengths.seed) {
        throw new Error(`${type} needs a ${pq.lengths.seed}-byte seed, got ${seed.length}`);
      }

      const keys = pq.keygen(seed);
      return {
        prv: { pkcs8pem: Buffer.from(keys.secretKey).toString("base64") },
        pub: { pkcs8pem: Buffer.from(keys.publicKey).toString("base64") },
      };
    }

    NodeCryptoProvider.requireSecp256k1(type);
    // secp256k1: the seed IS the scalar, so it has to be a valid one.
    if (seed.length !== 32) {
      throw new Error(`secp256k1 needs a 32-byte seed, got ${seed.length}`);
    }

    const scalar = BigInt("0x" + Buffer.from(seed).toString("hex"));
    if (scalar === BigInt(0) || scalar >= NodeCryptoProvider.SECP256K1_N) {
      // Refused, not reduced mod n. Reducing produces a perfectly functional
      // key belonging to a different identity, and nothing downstream ever
      // reports a problem.
      throw new Error(
        "seed is not a valid secp256k1 private key - the scalar must be in [1, n-1]",
      );
    }

    const curve = crypto.createECDH("secp256k1");
    curve.setPrivateKey(Buffer.from(seed));

    return {
      // The seed itself, not curve.getPrivateKey(), which strips leading
      // zero bytes - see generate() above.
      prv: { pkcs8pem: "0x" + Buffer.from(seed).toString("hex") },
      pub: {
        pkcs8pem:
          "0x" + curve.getPublicKey("hex", compressed ? "compressed" : "uncompressed"),
      },
    };
  }

  /**
   * Left-pad a big-endian scalar to a fixed byte length.
   *
   * @private
   */
  /**
   * The only non-post-quantum type this provider can MAKE is secp256k1.
   * Anything else used to fall through to secp256k1 silently - so asking for
   * an RSA key returned an EC one, and a caller signed with EC while believing
   * it was RSA. Refused instead. Signing and verifying an existing RSA key
   * (a legacy identity, e.g. a ledger's contract deployer) still works; only
   * generating one is out of scope.
   *
   * @private
   */
  private static requireSecp256k1(type?: string): void {
    if (type !== undefined && type !== "secp256k1") {
      throw new Error(
        `Cannot generate a "${type}" key - supported types are secp256k1, ml-dsa-65 and falcon-512`
      );
    }
  }

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
    const pem = this.toPrivatePem(prv.pkcs8pem);
    const signature = sign.sign(pem);

    // Low-S folding reads the signature as a DER (r, s) pair - an ECDSA
    // shape. An RSA signature is a single integer, so folding one threw
    // "Malformed ECDSA signature: expected R" and broke RSA signing
    // outright. That is not a hypothetical key type: the contract-deploy
    // identity on a Varnir network is RSA, and this stopped every deploy.
    if (crypto.createPrivateKey(pem).asymmetricKeyType !== "ec") {
      return signature.toString("base64");
    }

    return Buffer.from(NodeCryptoProvider.toLowS(signature)).toString("base64");
  }

  /**
   * secp256k1's group order, and the boundary between low and high S.
   *
   * @private
   */
  private static readonly SECP256K1_N = BigInt(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  );

  /**
   * Folds S into the lower half of the curve order.
   *
   * `(r, s)` and `(r, n - s)` are both valid signatures over the same message
   * under the same key - ECDSA malleability - so this changes nothing about
   * validity. OpenSSL does not normalise, and does not require it on verify,
   * so the ledger accepts either and this is not done for the ledger's sake.
   *
   * It is done because everything else in the ecosystem is stricter.
   * `@noble/curves` - which is what @activeledger/sdk-web signs and verifies
   * with - REJECTS high-S unless explicitly told not to, as do libsecp256k1
   * and Rust's k256. Without this, sdk-node emitted high-S roughly half the
   * time, so a signature made in Node failed against a verifier written with
   * those defaults about half the time. That presents as intermittent auth or
   * network trouble rather than as a signature format problem, and it has
   * already cost one team a live bug.
   *
   * It also makes sdk-node and sdk-web produce the same canonical form, which
   * they previously did not: sdk-web is deterministic and low-S via noble,
   * sdk-node is random-k through OpenSSL. They remain different signatures for
   * the same input - only RFC 6979 would change that, and OpenSSL exposes no
   * way to supply k - but they now agree on which half of the curve S sits in.
   *
   * Verification is deliberately NOT changed: it stays permissive, because the
   * ledger itself still produces high-S and rejecting those would be the same
   * bug pointed the other way.
   *
   * @private
   */
  private static toLowS(der: Buffer): Buffer {
    const { r, s } = NodeCryptoProvider.decodeDer(der);
    // BigInt(2) rather than 2n: this package targets below ES2020, where the
    // literal is a compile error, and raising the target would change what
    // consumers get.
    if (s <= NodeCryptoProvider.SECP256K1_N / BigInt(2)) {
      return der;
    }

    return NodeCryptoProvider.encodeDer(r, NodeCryptoProvider.SECP256K1_N - s);
  }

  /**
   * @private
   */
  private static decodeDer(der: Buffer): { r: Buffer; s: bigint } {
    let offset = 2;
    if (der[offset] !== 0x02) {
      throw new Error("Malformed ECDSA signature: expected R");
    }
    const rLength = der[offset + 1];
    const r = der.subarray(offset + 2, offset + 2 + rLength);

    offset += 2 + rLength;
    if (der[offset] !== 0x02) {
      throw new Error("Malformed ECDSA signature: expected S");
    }
    const sBytes = der.subarray(offset + 2, offset + 2 + der[offset + 1]);

    return { r, s: BigInt("0x" + sBytes.toString("hex")) };
  }

  /**
   * A DER INTEGER: minimal length, with a leading zero byte when the top bit
   * is set so the value is not read as negative.
   *
   * @private
   */
  private static derInteger(value: Buffer): Buffer {
    let trimmed = value;
    let start = 0;
    while (start < trimmed.length - 1 && trimmed[start] === 0) {
      start++;
    }
    trimmed = trimmed.subarray(start);
    if (trimmed[0] & 0x80) {
      trimmed = Buffer.concat([Buffer.from([0]), trimmed]);
    }

    return Buffer.concat([Buffer.from([0x02, trimmed.length]), trimmed]);
  }

  /**
   * @private
   */
  private static encodeDer(r: Buffer, s: bigint): Buffer {
    const body = Buffer.concat([
      NodeCryptoProvider.derInteger(r),
      NodeCryptoProvider.derInteger(Buffer.from(s.toString(16).padStart(64, "0"), "hex")),
    ]);

    return Buffer.concat([Buffer.from([0x30, body.length]), body]);
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
