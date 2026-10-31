import axios from "axios";
import { Connection, isCommitted } from "../connection";
import { IBaseTransaction } from "../interfaces";

jest.mock("axios", () => ({ __esModule: true, default: jest.fn() }));

const mockedAxios = axios as unknown as jest.Mock;

describe("Connection.sendTransaction", () => {
  const tx: IBaseTransaction = {
    $sigs: { a: "sig" },
    $tx: { $namespace: "default", $contract: "c", $i: { a: {} } },
  };

  beforeEach(() => mockedAxios.mockReset());

  it("POSTs the transaction as JSON to the baseURL built from the positional arguments", async () => {
    mockedAxios.mockResolvedValue({ data: { $umid: "u1", $summary: { commit: 1 } } });

    await new Connection("https", "node.example.com", 5260).sendTransaction(tx);

    const config = mockedAxios.mock.calls[0][0];
    expect(config.baseURL).toBe("https://node.example.com:5260");
    expect(config.method).toBe("POST");
    expect(config.headers).toEqual({ "Content-Type": "application/json" });
    expect(config.data).toBe(tx);
  });

  it("builds the same baseURL from an options object, with a string port", async () => {
    mockedAxios.mockResolvedValue({ data: { $summary: {} } });

    await new Connection({ protocol: "http", address: "10.0.0.1", portNumber: "5261" }).sendTransaction(tx);

    expect(mockedAxios.mock.calls[0][0].baseURL).toBe("http://10.0.0.1:5261");
  });

  it("resolves with the response body, not the axios envelope", async () => {
    const body = { $umid: "u2", $summary: { commit: 1 }, $streams: { new: [], updated: [] } };
    mockedAxios.mockResolvedValue({ data: body, status: 200 });

    await expect(new Connection("http", "h", 1).sendTransaction(tx)).resolves.toBe(body);
  });

  it("rejects with the transport error", async () => {
    const failure = new Error("connect ECONNREFUSED");
    mockedAxios.mockRejectedValue(failure);

    await expect(new Connection("http", "h", 1).sendTransaction(tx)).rejects.toBe(failure);
  });

  it("sends each transaction it is given, not the first one again", async () => {
    // The config object is reused between calls, so record data at call time
    const sent: unknown[] = [];
    mockedAxios.mockImplementation((config: { data: unknown }) => {
      sent.push(config.data);
      return Promise.resolve({ data: { $summary: {} } });
    });
    const connection = new Connection("http", "h", 1);
    const second: IBaseTransaction = { ...tx, $sigs: { b: "other" } };

    await connection.sendTransaction(tx);
    await connection.sendTransaction(second);

    expect(sent).toEqual([tx, second]);
  });
});

describe("Connection against a real HTTP server", () => {
  // jest.mock("axios") above stubs the transport, so these load the real one.
  const http = require("http") as typeof import("http");
  const realAxios = jest.requireActual("axios").default;

  const tx: IBaseTransaction = { $sigs: {}, $tx: { $namespace: "default", $contract: "c", $i: {} } };
  let server: import("http").Server;
  let reply: { status: number; body: string; type?: string };
  let port: number;

  beforeAll(async () => {
    server = http.createServer((_req, res) => {
      res.writeHead(reply.status, { "Content-Type": reply.type || "application/json" });
      res.end(reply.body);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as import("net").AddressInfo).port;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));
  beforeEach(() => mockedAxios.mockImplementation((config: unknown) => realAxios(config)));

  it.each([400, 404, 500, 502])("rejects a %i response rather than resolving its body", async (status) => {
    reply = { status, body: JSON.stringify({ $summary: { commit: 1 }, $streams: { new: [{ id: "x" }] } }) };

    await expect(new Connection("http", "127.0.0.1", port).sendTransaction(tx)).rejects.toMatchObject({
      response: { status },
    });
  });

  it.each([
    ["HTML", "<html>proxy page</html>", "text/html"],
    ["empty", "", "application/json"],
    ["a JSON string", '"ok"', "application/json"],
    ["a JSON array", "[]", "application/json"],
    ["an empty object", "{}", "application/json"],
    ["an object with no $summary", '{"$umid":"u","$streams":{"new":[{"id":"x"}]}}', "application/json"],
    ["a null $summary", '{"$summary":null}', "application/json"],
    ["a string $summary", '{"$summary":"ok"}', "application/json"],
  ])("rejects a 200 whose body is not a ledger reply (%s)", async (_n, body, type) => {
    reply = { status: 200, body, type };

    await expect(new Connection("http", "127.0.0.1", port).sendTransaction(tx)).rejects.toThrow(
      "Unexpected ledger response"
    );
  });

  it("still resolves a ledger rejection delivered as HTTP 200", async () => {
    const body = { $umid: "u", $summary: { total: 4, vote: 0, commit: 0, errors: ["1220 Signature Incorrect"] }, $streams: { new: [], updated: [] } };
    reply = { status: 200, body: JSON.stringify(body) };

    await expect(new Connection("http", "127.0.0.1", port).sendTransaction(tx)).resolves.toEqual(body);
  });
});

describe("Connection under concurrency and transport faults", () => {
  const http = require("http") as typeof import("http");
  const realAxios = jest.requireActual("axios").default;

  let server: import("http").Server;
  let port: number;
  let seen: string[];
  let release: (() => void)[];

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        if (req.url === "/") {
          seen.push(body);
          // Hold every reply until released, so the sends overlap in flight
          release.push(() => {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ $summary: { commit: 1 }, $umid: JSON.parse(body).$sigs.id }));
          });
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as import("net").AddressInfo).port;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));
  beforeEach(() => {
    seen = [];
    release = [];
    mockedAxios.mockImplementation((config: unknown) => realAxios(config));
  });

  const txFor = (id: string): IBaseTransaction => ({
    $sigs: { id },
    $tx: { $namespace: "default", $contract: "c", $i: {} },
  });

  it("keeps simultaneous sends on one Connection apart", async () => {
    const connection = new Connection("http", "127.0.0.1", port);

    const first = connection.sendTransaction(txFor("one"));
    const second = connection.sendTransaction(txFor("two"));
    const third = connection.sendTransaction(txFor("three"));
    while (release.length < 3) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    release.forEach((respond) => respond());

    // Each caller must get the reply to its own transaction, and the node must
    // have been sent three distinct bodies rather than one repeated.
    expect((await first).$umid).toBe("one");
    expect((await second).$umid).toBe("two");
    expect((await third).$umid).toBe("three");
    expect(seen.map((body) => JSON.parse(body).$sigs.id).sort()).toEqual(["one", "three", "two"]);
  });

  it("rejects when the node drops the connection before replying", async () => {
    const dropper = http.createServer((req) => req.socket.destroy());
    await new Promise<void>((resolve) => dropper.listen(0, "127.0.0.1", resolve));
    const dropPort = (dropper.address() as import("net").AddressInfo).port;

    try {
      await expect(new Connection("http", "127.0.0.1", dropPort).sendTransaction(txFor("x"))).rejects.toBeDefined();
    } finally {
      await new Promise<void>((resolve) => dropper.close(() => resolve()));
    }
  });
});

describe("isCommitted", () => {
  it.each([
    ["a summary with no errors", { $summary: { total: 1, vote: 1, commit: 1 } }],
    ["an empty errors list", { $summary: { errors: [] } }],
    ["a summary with commit 0 and no errors", { $summary: { total: 1, vote: 1, commit: 0 } }],
    ["an empty summary object", { $summary: {} }],
  ])("accepts %s", (_n, body) => expect(isCommitted(body)).toBe(true));

  it.each([
    ["an empty object", {}],
    ["no summary", { $streams: { new: [{ id: "x" }] } }],
    ["a null summary", { $summary: null }],
    ["an array summary", { $summary: [] }],
    ["errors", { $summary: { errors: ["1220 Signature Incorrect"] } }],
    ["a non-array errors value", { $summary: { errors: "nope" } }],
    ["null", null],
    ["undefined", undefined],
    ["a string", "ok"],
    ["an array", []],
  ])("refuses %s", (_n, body) => expect(isCommitted(body)).toBe(false));
});
