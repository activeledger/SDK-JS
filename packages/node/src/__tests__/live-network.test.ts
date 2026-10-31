import { Connection, isCommitted, KeyType, ILedgerResponse, IKey } from "@activeledger/sdk-core";
import { KeyHandler, TransactionHandler } from "../index";

/**
 * Runs against a real Activeledger network.
 *
 * Everything else here checks the SDK against vectors and the ledger's own
 * crypto library. This checks it against running nodes, which are the only
 * thing that decides whether a signature is acceptable: the type string, the
 * $sigs keying and the exact signed bytes are invisible to a unit test.
 *
 * Start the 4-node network from an activeledger checkout:
 *
 *   npm run test:network:serve
 *
 * then, with the URLs it prints:
 *
 *   AL_NODES=http://127.0.0.1:5510 AL_STORAGE=http://127.0.0.1:5509 \
 *     npx jest --config=jestconfig.json live-network
 *
 * Skipped when AL_NODES or AL_STORAGE is unset, so `npm test` works with no
 * ledger.
 */
const NODES = process.env.AL_NODES;
const STORAGE = process.env.AL_STORAGE;

const unique = (prefix: string) => `${prefix}${Date.now() % 100000000}${Math.floor(Math.random() * 1000)}`;

/** A transaction rejected at HTTP level rejects the promise; at ledger level it resolves with errors. */
async function committed(send: Promise<ILedgerResponse>): Promise<boolean> {
  try {
    return isCommitted(await send);
  } catch {
    return false;
  }
}

/** Reads a stream document from a node's storage service, which is only reachable on a local test network. */
async function authority(streamId: string): Promise<{ type: string; public: string } | undefined> {
  const storage = (STORAGE as string).split(",")[0];
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    const res = await fetch(`${storage}/activeledger/${encodeURIComponent(`${streamId}:stream`)}`);
    if (res.status === 200) {
      const doc = (await res.json()) as { authorities?: { type: string; public: string }[] };
      if (doc.authorities && doc.authorities.length) {
        return doc.authorities[0];
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`identity meta for ${streamId} never appeared in storage`);
}

if (!NODES || !STORAGE) {
  it.skip("live network (set AL_NODES and AL_STORAGE to run)", () => undefined);
} else {
  defineLiveTests(NODES);
}

function defineLiveTests(nodes: string) {
  describe("live network", () => {
    const url = new URL(nodes.split(",")[0]);
    const connection = new Connection(url.protocol.replace(":", ""), url.hostname, url.port);
    const keys = new KeyHandler();
    const txs = new TransactionHandler();

    const cases: [string, KeyType, boolean][] = [
      ["secp256k1 compressed", KeyType.EllipticCurve, true],
      ["secp256k1 uncompressed", KeyType.EllipticCurve, false],
      ["ml-dsa-65", KeyType.MLDSA65, false],
    ];

    for (const [name, type, compressed] of cases) {
      describe(name, () => {
        let key: IKey;

        const namespaceTx = async (prefix: string) =>
          txs.signTransaction(
            {
              $sigs: {},
              $tx: {
                $contract: "namespace",
                $i: { [key.identity as string]: { namespace: unique(prefix) } },
                $namespace: "default",
              },
            },
            key,
          );

        it("onboards, and the ledger records the key exactly", async () => {
          key = await keys.generateKey("identity", compressed, type);
          const response = await keys.onboardKey(key, connection);
          expect(isCommitted(response)).toBe(true);
          expect(key.identity).toBeTruthy();

          const recorded = await authority(key.identity as string);
          expect(recorded?.type).toBe(type);
          expect(recorded?.public).toBe(key.key.pub.pkcs8pem);
        });

        it("accepts a signed transaction", async () => {
          const response = await txs.sendTransaction(await namespaceTx("jsa"), connection);
          expect(isCommitted(response)).toBe(true);
        });

        it("accepts a labelled transaction", async () => {
          const tx = await txs.labelledTransaction({
            contract: "namespace",
            inputData: { namespace: unique("jsl") },
            inputLabel: key.identity as string,
            key,
            namespace: "default",
            stream: key.identity as string,
          });
          const response = await txs.sendTransaction(tx, connection);
          expect(isCommitted(response)).toBe(true);
        });

        it("does not commit a tampered transaction", async () => {
          const tx = await namespaceTx("jst");
          // Same signature, different body: signing again would make it valid.
          const input = tx.$tx.$i[key.identity as string];
          input.namespace = input.namespace + "x";
          expect(await committed(txs.sendTransaction(tx, connection))).toBe(false);
        });

        it("does not commit a transaction signed by another key", async () => {
          const other = await keys.generateKey("other", compressed, type);
          const tx = await namespaceTx("jso");
          // Replace the signature with one from a key the identity does not hold.
          tx.$sigs[key.identity as string] = await txs.signTransaction(JSON.stringify(tx.$tx), other);
          expect(await committed(txs.sendTransaction(tx, connection))).toBe(false);
        });
      });
    }
  });
}
