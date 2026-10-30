import { KeyType } from "@activeledger/sdk-core";
import { KeyHandler } from "../key.js";
import { PayloadHandler } from "../payload.js";
import { TransactionHandler } from "../transaction.js";
import { LedgerEvents } from "../events.js";
import { WebCryptoProvider } from "../crypto.js";
import { seedSize } from "../recovery.js";

describe("sdk-web PayloadHandler", () => {
  const keys = new KeyHandler();
  const payload = new PayloadHandler();

  for (const type of [KeyType.EllipticCurve, KeyType.MLDSA65, KeyType.Falcon512]) {
    it(`signs and verifies with a ${type} key, and rejects a changed payload`, async () => {
      const key = await keys.generateKey("maker", false, type);
      const order = { pair: "VNR/USDT", side: "sell" };
      const sig = payload.sign(order, key);

      expect(payload.verify(order, sig, key.key.pub.pkcs8pem, type)).toBe(true);
      expect(payload.verify({ pair: "VNR/USDT", side: "buy" }, sig, key.key.pub.pkcs8pem, type)).toBe(false);
    });
  }

  it("returns false rather than throwing on a junk signature", async () => {
    const key = await keys.generateKey("maker");

    expect(payload.verify({ a: 1 }, "not-a-signature", key.key.pub.pkcs8pem)).toBe(false);
    expect(payload.verify({ a: 1 }, "", key.key.pub.pkcs8pem)).toBe(false);
  });

  it("verifies against the canonical string identically to the object", async () => {
    const key = await keys.generateKey("maker");
    const order = { b: 2, a: 1 };
    const sig = payload.sign(order, key);

    expect(payload.verify(payload.canonical(order), sig, key.key.pub.pkcs8pem)).toBe(true);
  });
});

describe("sdk-web TransactionHandler", () => {
  const keys = new KeyHandler();
  const txs = new TransactionHandler();

  it("builds an onboard transaction whose self-signature verifies", async () => {
    const key = await keys.generateKey("alice");
    const tx = await txs.buildOnboardKeyTx(key);

    expect(tx.$selfsign).toBe(true);
    expect(tx.$tx.$i.alice.publicKey).toBe(key.key.pub.pkcs8pem);
    expect(tx.$tx.$i.alice.type).toBe(KeyType.EllipticCurve);
    expect(
      new WebCryptoProvider().verify(JSON.stringify(tx.$tx), tx.$sigs.alice, key.key.pub, key.type)
    ).toBe(true);
  });

  it("signs a transaction under a post-quantum key", async () => {
    const key = await keys.generateKey("pq", false, KeyType.Falcon512);
    const tx = await txs.buildOnboardKeyTx(key);

    expect(tx.$tx.$i.pq.type).toBe(KeyType.Falcon512);
    expect(new WebCryptoProvider().verify(JSON.stringify(tx.$tx), tx.$sigs.pq, key.key.pub, key.type)).toBe(true);
  });

  it("a signature does not verify once the transaction body changes", async () => {
    const key = await keys.generateKey("alice");
    const tx = await txs.buildOnboardKeyTx(key);
    const tampered = { ...tx.$tx, $contract: "other" };

    expect(new WebCryptoProvider().verify(JSON.stringify(tampered), tx.$sigs.alice, key.key.pub, key.type)).toBe(false);
  });

  it("signs a string body and returns just the signature", async () => {
    const key = await keys.generateKey("alice");
    const sig = await txs.signTransaction("raw body", key);

    expect(new WebCryptoProvider().verify("raw body", sig, key.key.pub, key.type)).toBe(true);
  });

  it("labelledTransaction refuses a key without an identity", async () => {
    const key = await keys.generateKey("alice");

    await expect(
      txs.labelledTransaction({
        key,
        namespace: "default",
        contract: "c",
        inputLabel: "in",
        inputData: {},
        stream: "s",
      })
    ).rejects.toThrow("Key must have an identity.");
  });

  it("labelledTransaction signs under the identity and carries the stream", async () => {
    const key = await keys.generateKey("alice");
    key.identity = "stream-1";
    const tx = await txs.labelledTransaction({
      key,
      namespace: "default",
      contract: "c",
      inputLabel: "in",
      inputData: { n: 1 },
      stream: "stream-1",
    });

    expect(tx.$tx.$i.in).toEqual({ n: 1, $stream: "stream-1" });
    expect(Object.keys(tx.$sigs)).toEqual(["stream-1"]);
    expect(new WebCryptoProvider().verify(JSON.stringify(tx.$tx), tx.$sigs["stream-1"], key.key.pub, key.type)).toBe(
      true
    );
  });
});

describe("sdk-web KeyHandler", () => {
  const keys = new KeyHandler();

  it("generateBIP39Key yields a phrase that restores the same key", async () => {
    const made = await keys.generateBIP39Key("k");
    const again = await keys.restoreBIP39Key("k", made.phrase as string);

    expect((made.phrase as string).split(" ")).toHaveLength(12);
    expect(again.key).toEqual(made.key);
  });

  it("restoreBIP39Key refuses an invalid phrase", async () => {
    await expect(keys.restoreBIP39Key("k", "not a real mnemonic phrase")).rejects.toThrow();
  });

  it("restoreBIP39Key refuses the legacy scheme for a post-quantum type", async () => {
    const phrase = (await keys.generateBIP39Key("k")).phrase as string;

    await expect(keys.restoreBIP39Key("k", phrase, { legacy: true, type: KeyType.Falcon512 })).rejects.toThrow(
      "legacy BIP-39 scheme is secp256k1 only"
    );
  });
});

describe("sdk-web LedgerEvents", () => {
  const g = globalThis as any;
  const original = g.EventSource;
  let created: Array<{ url: string; listeners: Record<string, Function> }>;

  beforeEach(() => {
    created = [];
    g.EventSource = class {
      public listeners: Record<string, Function> = {};
      constructor(public url: string) {
        created.push(this);
      }
      addEventListener(name: string, fn: Function) {
        this.listeners[name] = fn;
      }
      close() {}
    };
  });
  afterEach(() => {
    g.EventSource = original;
  });

  it("opens the platform's global EventSource at the activity URL", () => {
    new LedgerEvents("http://host:5261").subscribeToActivity("abc", () => undefined);

    expect(created.map((c) => c.url)).toEqual(["http://host:5261/api/activity/subscribe/abc"]);
  });

  it("hands the callback the stream from each message", () => {
    const received: unknown[] = [];
    new LedgerEvents("http://host:5261").subscribeToActivity((s: unknown) => received.push(s));

    created[0].listeners.message({ data: JSON.stringify({ stream: { id: "s1" } }) });
    expect(received).toEqual([{ id: "s1" }]);
  });

  it("rejects a URL without a protocol", () => {
    expect(() => new LedgerEvents("host:5261")).toThrow("Activecore URL must include http:// or https://");
  });
});

describe("sdk-web edge cases", () => {
  it("seedSize refuses a key type that has no seed derivation", () => {
    expect(() => seedSize("nope" as KeyType)).toThrow("nope keys cannot be derived from a seed");
  });

  it("an ML-DSA verify with a wrong-length public key is false, not a throw", () => {
    const provider = new WebCryptoProvider();
    const key = provider.generate(false, "ml-dsa-65");
    const sig = provider.sign("data", key.prv, "ml-dsa-65");

    expect(provider.verify("data", sig, key.pub, "ml-dsa-65")).toBe(true);
    expect(provider.verify("data", sig, { pkcs8pem: "AAAA" }, "ml-dsa-65")).toBe(false);
  });
});
