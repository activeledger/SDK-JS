import { PayloadHandler } from "../payload";
import { ICryptoProvider, IKey, IKeyHandleDetails } from "../interfaces";
import { KeyType } from "../enums";

/** Records what it is asked, and can be told to throw on verify. */
class SpyCryptoProvider implements ICryptoProvider {
  public verifyError: Error | null = null;
  public signCalls: unknown[][] = [];
  public verifyCalls: unknown[][] = [];

  public generate(): any {
    throw new Error("not used");
  }

  public sign(data: string, prv: IKeyHandleDetails, type?: string): string {
    this.signCalls.push([data, prv, type]);
    return "sig";
  }

  public verify(data: string, signature: string, pub: IKeyHandleDetails, type?: string): boolean {
    this.verifyCalls.push([data, signature, pub, type]);
    if (this.verifyError) {
      throw this.verifyError;
    }
    return true;
  }
}

const key: IKey = {
  name: "k",
  type: KeyType.Falcon512,
  key: { prv: { pkcs8pem: "prv" }, pub: { pkcs8pem: "pub" } },
};

describe("PayloadHandler", () => {
  it("signs the canonical form with the key's private half and scheme", () => {
    const provider = new SpyCryptoProvider();
    const sig = new PayloadHandler(provider).sign({ b: 2, a: 1 }, key);

    expect(sig).toBe("sig");
    expect(provider.signCalls).toEqual([['{"b":2,"a":1}', { pkcs8pem: "prv" }, KeyType.Falcon512]]);
  });

  it("verifies against the canonical form, wrapping the public key", () => {
    const provider = new SpyCryptoProvider();

    expect(new PayloadHandler(provider).verify({ a: 1 }, "sig", "pub", "falcon-512")).toBe(true);
    expect(provider.verifyCalls).toEqual([['{"a":1}', "sig", { pkcs8pem: "pub" }, "falcon-512"]]);
  });

  it("returns false, not a throw, when the provider throws on malformed input", () => {
    const provider = new SpyCryptoProvider();
    provider.verifyError = new Error("bad signature encoding");

    expect(new PayloadHandler(provider).verify({ a: 1 }, "junk", "pub")).toBe(false);
    expect(provider.verifyCalls).toHaveLength(1);
  });
});
