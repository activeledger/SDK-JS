import { ICryptoProvider, IKey, IKeyHandleDetails, IKeyHandler } from "../interfaces";
import { KeyType } from "../enums";
import { TransactionHandler } from "../transaction";
import { KeyHandler } from "../key";
import { Connection } from "../connection";

/**
 * A deterministic stub crypto provider - core's job is orchestrating
 * transaction building/signing, not cryptography itself, so these tests
 * verify that orchestration without depending on a real curve
 * implementation. Real crypto is covered by sdk-node's and sdk-web's own
 * provider tests.
 */
class StubCryptoProvider implements ICryptoProvider {
  public generate(compressed?: boolean): IKeyHandler {
    return {
      prv: { pkcs8pem: "0xprivate" },
      pub: { pkcs8pem: compressed ? "0xpublic-compressed" : "0xpublic" },
    };
  }

  public sign(data: string, prv: IKeyHandleDetails): string {
    return `signed(${prv.pkcs8pem}):${data}`;
  }

  public verify(data: string, signature: string, pub: IKeyHandleDetails): boolean {
    return signature === `signed(0xprivate):${data}` && pub.pkcs8pem === "0xpublic";
  }
}

describe("KeyHandler.generateKey", () => {
  it("generates a key with the given name and secp256k1 type", async () => {
    const handler = new KeyHandler(new StubCryptoProvider());
    const key = await handler.generateKey("mykey");

    expect(key.name).toBe("mykey");
    expect(key.type).toBe(KeyType.EllipticCurve);
    expect(key.key.prv.pkcs8pem).toBe("0xprivate");
    expect(key.key.pub.pkcs8pem).toBe("0xpublic");
  });

  it("passes compressed through to the crypto provider", async () => {
    const handler = new KeyHandler(new StubCryptoProvider());
    const key = await handler.generateKey("mykey", true);

    expect(key.key.pub.pkcs8pem).toBe("0xpublic-compressed");
  });
});

describe("TransactionHandler.buildOnboardKeyTx", () => {
  it("builds a self-signed onboard transaction containing the key's public key", async () => {
    const provider = new StubCryptoProvider();
    const key: IKey = { name: "mykey", type: KeyType.EllipticCurve, key: provider.generate() };
    const tx = await new TransactionHandler(provider).buildOnboardKeyTx(key);

    expect(tx.$selfsign).toBe(true);
    expect(tx.$tx.$contract).toBe("onboard");
    expect(tx.$tx.$namespace).toBe("default");
    expect(tx.$tx.$i.mykey.publicKey).toBe("0xpublic");
    expect(tx.$tx.$i.mykey.type).toBe(KeyType.EllipticCurve);
    // Signed by name, since the key has no identity yet
    expect(tx.$sigs.mykey).toBe(`signed(0xprivate):${JSON.stringify(tx.$tx)}`);
  });

  it("honours a custom contract/namespace", async () => {
    const provider = new StubCryptoProvider();
    const key: IKey = { name: "mykey", type: KeyType.EllipticCurve, key: provider.generate() };
    const tx = await new TransactionHandler(provider).buildOnboardKeyTx(key, {
      contract: "customOnboard",
      namespace: "myapp",
    });

    expect(tx.$tx.$contract).toBe("customOnboard");
    expect(tx.$tx.$namespace).toBe("myapp");
  });
});

describe("TransactionHandler.labelledTransaction", () => {
  it("rejects when the key has no identity", async () => {
    const provider = new StubCryptoProvider();
    const key: IKey = { name: "mykey", type: KeyType.EllipticCurve, key: provider.generate() };

    await expect(
      new TransactionHandler(provider).labelledTransaction(
        key,
        "default",
        "mycontract",
        "input",
        { amount: 1 },
        "stream-id",
      ),
    ).rejects.toThrow("Key must have an identity.");
  });

  it("signs with the key's identity once it has one", async () => {
    const provider = new StubCryptoProvider();
    const key: IKey = {
      name: "mykey",
      type: KeyType.EllipticCurve,
      key: provider.generate(),
      identity: "stream-abc123",
    };

    const tx = await new TransactionHandler(provider).labelledTransaction(
      key,
      "default",
      "mycontract",
      "input",
      { amount: 1 },
      "stream-id",
    );

    expect(tx.$tx.$i.input).toEqual({ amount: 1, $stream: "stream-id" });
    expect(tx.$sigs["stream-abc123"]).toBe(`signed(0xprivate):${JSON.stringify(tx.$tx)}`);
  });

  /**
   * The real node's self-signed verification path
   * (packages/protocol/src/protocol/process.ts, main activeledger repo)
   * loops every $tx.$i key and looks up `$sigs[thatKey]` - never the
   * signer's identity - and separately requires `$i[thatKey].publicKey`
   * (used directly, no ledger lookup, since there's no existing stream
   * yet to fetch an authority from). Live-confirmed against a real node
   * this session: without both of these, deploy/namespace-claim/attestation
   * transactions (anything using labelledTransaction with selfsign: true)
   * are rejected with "Self signed signature not found" - the identity-keyed
   * default above is only correct for the non-self-signed case.
   */
  it("self-signed: keys $sigs by the input label and embeds publicKey/type, not the identity", async () => {
    const provider = new StubCryptoProvider();
    const key: IKey = {
      name: "mykey",
      type: KeyType.EllipticCurve,
      key: provider.generate(),
      identity: "stream-abc123",
    };

    const tx = await new TransactionHandler(provider).labelledTransaction(
      key,
      "default",
      "contract",
      "contract",
      { namespace: "myns", name: "mycontract", version: "1", contract: "base64source" },
      "stream-abc123",
      undefined,
      undefined,
      undefined,
      true,
    );

    expect(tx.$selfsign).toBe(true);
    expect(tx.$tx.$i.contract).toEqual({
      namespace: "myns",
      name: "mycontract",
      version: "1",
      contract: "base64source",
      $stream: "stream-abc123",
      publicKey: "0xpublic",
      type: KeyType.EllipticCurve,
    });
    // Keyed by the input label ("contract"), never the identity.
    expect(tx.$sigs["contract"]).toBe(`signed(0xprivate):${JSON.stringify(tx.$tx)}`);
    expect(tx.$sigs["stream-abc123"]).toBeUndefined();
  });
});

describe("Connection", () => {
  it("builds the expected baseURL from protocol/address/port", () => {
    // No network call here - just verifying the constructor doesn't throw
    // for either overload shape.
    expect(() => new Connection("http", "localhost", 5260)).not.toThrow();
    expect(
      () => new Connection({ protocol: "https", address: "node.example.com", portNumber: 443 }),
    ).not.toThrow();
  });
});
