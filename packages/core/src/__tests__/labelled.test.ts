import { ICryptoProvider, IKey, IKeyHandleDetails, IKeyHandler } from "../interfaces";
import { KeyType } from "../enums";
import { TransactionHandler } from "../transaction";
import { KeyHandler } from "../key";

class StubCryptoProvider implements ICryptoProvider {
  public generate(): IKeyHandler {
    return { prv: { pkcs8pem: "0xprivate" }, pub: { pkcs8pem: "0xpublic" } };
  }
  public sign(data: string, prv: IKeyHandleDetails): string {
    return `signed(${prv.pkcs8pem}):${data}`;
  }
  public verify(): boolean {
    return true;
  }
}

const identified = (provider: ICryptoProvider): IKey => ({
  name: "mykey",
  type: KeyType.EllipticCurve,
  key: provider.generate(),
  identity: "stream-abc",
});

describe("TransactionHandler.labelledTransaction options", () => {
  it("accepts an options object and includes entry, outputs and readonly", async () => {
    const provider = new StubCryptoProvider();
    const tx = await new TransactionHandler(provider).labelledTransaction({
      key: identified(provider),
      namespace: "ns",
      contract: "c",
      inputLabel: "in",
      inputData: { a: 1 },
      stream: "target",
      entry: "transfer",
      outputs: { out: { b: 2 } },
      readonly: { ro: "stream-x" },
    });

    expect(tx.$tx.$namespace).toBe("ns");
    expect(tx.$tx.$contract).toBe("c");
    expect(tx.$tx.$entry).toBe("transfer");
    expect(tx.$tx.$o).toEqual({ out: { b: 2 } });
    expect(tx.$tx.$r).toEqual({ ro: "stream-x" });
    expect(tx.$tx.$i.in).toEqual({ a: 1, $stream: "target" });
    expect(tx.$selfsign).toBeUndefined();
  });

  it("omits $entry, $o and $r when not supplied", async () => {
    const provider = new StubCryptoProvider();
    const tx = await new TransactionHandler(provider).labelledTransaction(
      identified(provider), "ns", "c", "in", {}, "target"
    );

    expect(Object.keys(tx.$tx).sort()).toEqual(["$contract", "$i", "$namespace"]);
  });

  it("maps positional entry, outputs and readonly the same way", async () => {
    const provider = new StubCryptoProvider();
    const tx = await new TransactionHandler(provider).labelledTransaction(
      identified(provider), "ns", "c", "in", {}, "target", "e", { o: 1 }, { r: 2 }
    );

    expect(tx.$tx.$entry).toBe("e");
    expect(tx.$tx.$o).toEqual({ o: 1 });
    expect(tx.$tx.$r).toEqual({ r: 2 });
  });

  it("does not mutate the caller's inputData", async () => {
    const provider = new StubCryptoProvider();
    const data = { a: 1 };
    await new TransactionHandler(provider).labelledTransaction(
      identified(provider), "ns", "c", "in", data, "target"
    );

    expect(data).toEqual({ a: 1 });
  });
});

describe("TransactionHandler.signTransaction", () => {
  it("returns just the signature for a string body", async () => {
    const provider = new StubCryptoProvider();
    const sig = await new TransactionHandler(provider).signTransaction("raw", identified(provider));

    expect(sig).toBe("signed(0xprivate):raw");
  });

  it("rejects when the provider throws", async () => {
    const provider = new StubCryptoProvider();
    provider.sign = () => {
      throw new Error("no good");
    };

    await expect(new TransactionHandler(provider).signTransaction("raw", identified(provider))).rejects.toThrow(
      "no good"
    );
  });
});

describe("KeyHandler.generateKeyFromSeed", () => {
  it("rejects with a clear error when the provider has no seed support", async () => {
    await expect(
      new KeyHandler(new StubCryptoProvider()).generateKeyFromSeed("k", new Uint8Array(32))
    ).rejects.toThrow("does not implement generateFromSeed");
  });

  it("passes seed, compressed and type to the provider", async () => {
    const calls: unknown[][] = [];
    const provider = Object.assign(new StubCryptoProvider(), {
      generateFromSeed: (...args: unknown[]) => {
        calls.push(args);
        return { prv: { pkcs8pem: "p" }, pub: { pkcs8pem: "q" } };
      },
    });
    const seed = new Uint8Array(48);
    const key = await new KeyHandler(provider).generateKeyFromSeed("k", seed, true, KeyType.Falcon512);

    expect(calls).toEqual([[seed, true, KeyType.Falcon512]]);
    expect(key).toMatchObject({ name: "k", type: KeyType.Falcon512 });
  });
});
