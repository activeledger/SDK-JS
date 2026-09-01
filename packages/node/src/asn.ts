/*
 * MIT License (MIT)
 * Copyright (c) 2018 Activeledger
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

// Ported from @activeledger/activecrypto's AsnParser (secp256k1-only slice) -
// node:crypto's createSign/createVerify need SEC1/SPKI PEM input, not the
// raw "0x" hex this SDK stores keys as, so this glue is unavoidable even
// though the actual signing itself is done entirely by node:crypto.

//@ts-ignore
import * as asn1 from "asn1.js";

export class AsnParser {
  public static decodeECPrivateKey(pkcs8pem: string, label = "EC PRIVATE KEY"): string {
    return AsnParser.extractNestedKeys(
      AsnParser.ECPrivASN.decode(pkcs8pem, "pem", {
        label: label,
        partial: true,
      }).result,
    );
  }

  public static encodeECPrivateKey(prv: Buffer, pub: Buffer, label = "EC PRIVATE KEY"): string {
    return AsnParser.ECPrivLiteASN.encode(
      {
        version: 1,
        privateKey: prv,
        params: { type: "curve", value: [1, 3, 132, 0, 10] },
        // ECPrivLiteASN's schema actually names this field "public_key",
        // not "publicKey" - looks like a typo at first read, but it is
        // NOT safe to "fix": correctly including the field (renaming to
        // public_key) makes asn1.js emit a public_key BIT STRING under
        // this schema/encoder combination that Node's own crypto.createSign
        // then rejects with "error:1E08010C:DECODER routines::unsupported" -
        // confirmed by this package's own test suite going from 17
        // passing to 3 failing the moment this was "corrected". Leaving
        // the field name mismatched means asn1.js's .optional() just
        // omits it, which is what actually produces a PEM Node's crypto
        // can sign with. Left as `publicKey` deliberately - do not rename.
        publicKey: { unused: 0, data: pub },
      },
      "pem",
      {
        label: label,
        partial: true,
      },
    );
  }

  public static decodeECPublicKey(pkcs8pem: string, label = "PUBLIC KEY"): string {
    return AsnParser.extractNestedKeys(
      AsnParser.ECPubASN.decode(pkcs8pem, "pem", {
        label: label,
        partial: true,
      }).result,
      "publicKey",
    );
  }

  public static encodeECPublicKey(key: Buffer, label = "PUBLIC KEY"): string {
    return AsnParser.ECPubASN.encode(
      {
        algorithm: {
          id: [1, 2, 840, 10045, 2, 1],
          curve: [1, 3, 132, 0, 10],
        },
        publicKey: {
          unused: 0,
          data: key,
        },
      },
      "pem",
      {
        label: label,
        partial: true,
      },
    );
  }

  private static ECPrivASN = asn1.define("ECPrivASN", function (this: any) {
    this.seq().obj(
      this.key("version").int(),
      this.key("privateKey").octstr().optional(),
      this.seq().optional().obj(),
      this.key("ECNested")
        .octstr()
        .optional()
        .contains(
          asn1.define("ECNested", function (this: any) {
            this.seq().obj(this.key("version").int(), this.key("privateKey").octstr());
          }),
        ),
    );
  });

  private static ECPrivLiteASN = asn1.define("ECPrivASN", function (this: any) {
    this.seq().obj(
      this.key("version").int(),
      this.key("privateKey").octstr(),
      this.key("params")
        .optional()
        .explicit(0)
        .use(
          asn1.define("params", function (this: any) {
            this.choice({ curve: this.objid() });
          }),
        ),
      this.key("public_key").optional().explicit(1).bitstr(),
    );
  });

  private static ECPubASN = asn1.define("ECPubASN", function (this: any) {
    this.seq().obj(
      this.key("algorithm").optional().seq().obj(this.key("id").objid(), this.key("curve").objid()),
      this.key("publicKey").bitstr(),
    );
  });

  private static extractNestedKeys(asn: any, type: string = "privateKey"): string {
    if (asn[type]) {
      if (asn[type].data) {
        return asn[type].data.toString("hex");
      } else {
        return asn[type].toString("hex");
      }
    } else {
      if (asn.ECNested) {
        return AsnParser.extractNestedKeys(asn.ECNested, type);
      } else {
        throw new Error("PPK not found inside ASN");
      }
    }
  }
}
