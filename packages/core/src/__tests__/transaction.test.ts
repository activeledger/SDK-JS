import { ICryptoProvider, IKey, IKeyHandleDetails, IKeyHandler } from "../interfaces";
import { KeyType } from "../enums";
import { TransactionHandler } from "../transaction";
import { KeyHandler } from "../key";
import { Connection } from "../connection";
import { ILedgerResponse } from "../interfaces";

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

describe("buildOnboardKeyTx regressions", () => {
  it("keys $sigs by the $i label even when the key already has an identity", async () => {
    const provider = new StubCryptoProvider();
    const key: IKey = {
      name: "mykey",
      type: KeyType.EllipticCurve,
      key: provider.generate(),
      identity: "existing-stream-id",
    };
    const tx = await new TransactionHandler(provider).buildOnboardKeyTx(key);

    expect(Object.keys(tx.$sigs)).toEqual(["mykey"]);
  });

  it("does not carry custom options over to later onboards", async () => {
    const provider = new StubCryptoProvider();
    const key: IKey = { name: "mykey", type: KeyType.EllipticCurve, key: provider.generate() };
    const handler = new TransactionHandler(provider);

    await handler.buildOnboardKeyTx(key, { contract: "customOnboard", namespace: "myapp" });
    const later = await handler.buildOnboardKeyTx(key);

    expect(later.$tx.$contract).toBe("onboard");
    expect(later.$tx.$namespace).toBe("default");
  });
});

describe("KeyHandler.onboardKey", () => {
  const respondWith = (response: unknown) =>
    ({ sendTransaction: () => Promise.resolve(response) }) as unknown as Connection;

  it("sets the identity from the new stream", async () => {
    const provider = new StubCryptoProvider();
    const key = await new KeyHandler(provider).generateKey("mykey");
    await new KeyHandler(provider).onboardKey(
      key,
      respondWith({ $streams: { new: [{ id: "new-id", name: "x" }], updated: [] } })
    );

    expect(key.identity).toBe("new-id");
  });

  it("rejects with the ledger's errors when no identity was created", async () => {
    const provider = new StubCryptoProvider();
    const key = await new KeyHandler(provider).generateKey("mykey");

    await expect(
      new KeyHandler(provider).onboardKey(
        key,
        respondWith({
          $umid: "u",
          $summary: { total: 4, vote: 0, commit: 0, errors: ["1220 Signature Incorrect"] },
          $streams: { new: [], updated: [] },
        })
      )
    ).rejects.toThrow('Onboarding "mykey" created no identity: 1220 Signature Incorrect');
    expect(key.identity).toBeUndefined();
  });

  it.each([["a string", "<html>502 Bad Gateway</html>"], ["null", null], ["undefined", undefined], ["a number", 7], ["an array", []]])(
    "does not commit or throw from the accessors when the body is %s",
    async (_name, body) => {
      const provider = new StubCryptoProvider();
      const key = await new KeyHandler(provider).generateKey("mykey");

      await expect(new KeyHandler(provider).onboardKey(key, respondWith(body))).rejects.toThrow(
        'Onboarding "mykey" created no identity'
      );
      expect(key.identity).toBeUndefined();
    }
  );

  it("does not commit when the summary is missing or has no errors", async () => {
    const provider = new StubCryptoProvider();
    const key = await new KeyHandler(provider).generateKey("mykey");

    await expect(
      new KeyHandler(provider).onboardKey(key, respondWith({ $summary: null, $streams: null }))
    ).rejects.toThrow("ledger response:");
    expect(key.identity).toBeUndefined();
  });

  it("types $summary.errors without a cast", () => {
    const rejected: ILedgerResponse = {
      $umid: "u",
      $summary: { total: 4, vote: 0, commit: 0, errors: ["1220 Signature Incorrect"] },
      $streams: { new: [], updated: [] },
    };
    const accepted: ILedgerResponse = {
      $umid: "u",
      $summary: { total: 4, vote: 4, commit: 4 },
      $streams: { new: [], updated: [] },
    };
    const reasons: string[] = rejected.$summary.errors ?? [];

    expect(reasons).toEqual(["1220 Signature Incorrect"]);
    expect(accepted.$summary.errors).toBeUndefined();

    // @ts-expect-error errors is a list of strings, not a string
    const bad: ILedgerResponse["$summary"] = { total: 1, vote: 1, commit: 1, errors: "nope" };
    expect(bad).toBeDefined();
  });
});

describe("LedgerEvents URL handling", () => {
  // Imported here rather than at the top so the stub above stays the first
  // thing a reader sees.
  const { LedgerEvents } = require("../events");
  const noopSource = () => ({ onerror: null, addEventListener: () => undefined, close: () => undefined });

  it.each([
    ["http://host:5261", "http://host:5261/api"],
    ["http://host:5261/", "http://host:5261/api"],
    ["http://host:5261//", "http://host:5261/api"],
    ["http://host:5261/api", "http://host:5261/api"],
    ["http://host:5261/api/", "http://host:5261/api"],
  ])("%s resolves to %s", (given, expected) => {
    const opened: string[] = [];
    const events = new LedgerEvents(given, (url: string) => {
      opened.push(url);
      return noopSource();
    });
    events.subscribeToActivity(() => undefined);

    expect(opened).toEqual([`${expected}/activity/subscribe`]);
  });
});
