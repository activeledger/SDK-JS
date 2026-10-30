import * as crypto from "crypto";
import { AsnParser } from "../asn";

/** A secp256k1 keypair from node:crypto, with its raw scalar and point. */
function nodeKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  const jwk = privateKey.export({ format: "jwk" }) as { d: string; x: string; y: string };
  const prv = Buffer.from(jwk.d, "base64url");
  const pub = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]);
  return { privateKey, publicKey, prv, pub };
}

const toPem = (label: string, der: Buffer): string =>
  `-----BEGIN ${label}-----\n${der.toString("base64").replace(/(.{64})/g, "$1\n")}\n-----END ${label}-----\n`;

describe("AsnParser private keys", () => {
  it("decodes a SEC1 PEM written by node:crypto back to the scalar", () => {
    const { privateKey, prv } = nodeKey();
    const pem = privateKey.export({ type: "sec1", format: "pem" }) as string;

    expect(AsnParser.decodeECPrivateKey(pem)).toBe(prv.toString("hex"));
  });

  it("decodes a PKCS8 PEM (the key is nested inside an octet string)", () => {
    const { privateKey, prv } = nodeKey();
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

    expect(AsnParser.decodeECPrivateKey(pem, "PRIVATE KEY")).toBe(prv.toString("hex"));
  });

  it("round-trips encode then decode", () => {
    const { prv, pub } = nodeKey();

    expect(AsnParser.decodeECPrivateKey(AsnParser.encodeECPrivateKey(prv, pub))).toBe(prv.toString("hex"));
  });

  it("emits a PEM that node:crypto can sign with", () => {
    const { prv, pub, publicKey } = nodeKey();
    const pem = AsnParser.encodeECPrivateKey(prv, pub);

    const sig = crypto.sign("sha256", Buffer.from("hello"), pem);
    expect(crypto.verify("sha256", Buffer.from("hello"), publicKey, sig)).toBe(true);
    expect(crypto.verify("sha256", Buffer.from("other"), publicKey, sig)).toBe(false);
  });

  it("honours a custom PEM label on both sides", () => {
    const { prv, pub } = nodeKey();
    const pem = AsnParser.encodeECPrivateKey(prv, pub, "CUSTOM KEY");

    expect(pem).toContain("-----BEGIN CUSTOM KEY-----");
    expect(AsnParser.decodeECPrivateKey(pem, "CUSTOM KEY")).toBe(prv.toString("hex"));
    expect(() => AsnParser.decodeECPrivateKey(pem)).toThrow();
  });

  it("throws when the structure holds no private key", () => {
    // SEQUENCE { INTEGER 1 } - decodes, but there is nothing to extract.
    const pem = toPem("EC PRIVATE KEY", Buffer.from("3003020101", "hex"));

    expect(() => AsnParser.decodeECPrivateKey(pem)).toThrow("PPK not found inside ASN");
  });

  it("throws on a PEM that is not DER", () => {
    const pem = toPem("EC PRIVATE KEY", Buffer.from("not der at all"));

    expect(() => AsnParser.decodeECPrivateKey(pem)).toThrow();
  });
});

describe("AsnParser public keys", () => {
  it("decodes an SPKI PEM written by node:crypto back to the point", () => {
    const { publicKey, pub } = nodeKey();
    const pem = publicKey.export({ type: "spki", format: "pem" }) as string;

    expect(AsnParser.decodeECPublicKey(pem)).toBe(pub.toString("hex"));
  });

  it("round-trips encode then decode", () => {
    const { pub } = nodeKey();

    expect(AsnParser.decodeECPublicKey(AsnParser.encodeECPublicKey(pub))).toBe(pub.toString("hex"));
  });

  it("emits an SPKI PEM that node:crypto parses as secp256k1", () => {
    const { pub, publicKey } = nodeKey();
    const parsed = crypto.createPublicKey(AsnParser.encodeECPublicKey(pub));

    expect(parsed.asymmetricKeyType).toBe("ec");
    expect(parsed.asymmetricKeyDetails?.namedCurve).toBe("secp256k1");
    expect(parsed.export({ type: "spki", format: "der" }).equals(publicKey.export({ type: "spki", format: "der" }))).toBe(
      true
    );
  });

  it("honours a custom PEM label on both sides", () => {
    const { pub } = nodeKey();
    const pem = AsnParser.encodeECPublicKey(pub, "CUSTOM PUB");

    expect(pem).toContain("-----BEGIN CUSTOM PUB-----");
    expect(AsnParser.decodeECPublicKey(pem, "CUSTOM PUB")).toBe(pub.toString("hex"));
  });

  it("throws on a PEM that is not DER", () => {
    expect(() => AsnParser.decodeECPublicKey(toPem("PUBLIC KEY", Buffer.from("junk")))).toThrow();
  });

  it("throws when the label does not match the PEM", () => {
    const { publicKey } = nodeKey();
    const pem = publicKey.export({ type: "spki", format: "pem" }) as string;

    expect(() => AsnParser.decodeECPublicKey(pem, "EC PUBLIC KEY")).toThrow();
  });
});
