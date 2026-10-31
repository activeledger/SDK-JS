import axios from "axios";
import { Connection } from "../connection";
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
    mockedAxios.mockResolvedValue({ data: { $umid: "u1" } });

    await new Connection("https", "node.example.com", 5260).sendTransaction(tx);

    const config = mockedAxios.mock.calls[0][0];
    expect(config.baseURL).toBe("https://node.example.com:5260");
    expect(config.method).toBe("POST");
    expect(config.headers).toEqual({ "Content-Type": "application/json" });
    expect(config.data).toBe(tx);
  });

  it("builds the same baseURL from an options object, with a string port", async () => {
    mockedAxios.mockResolvedValue({ data: {} });

    await new Connection({ protocol: "http", address: "10.0.0.1", portNumber: "5261" }).sendTransaction(tx);

    expect(mockedAxios.mock.calls[0][0].baseURL).toBe("http://10.0.0.1:5261");
  });

  it("resolves with the response body, not the axios envelope", async () => {
    const body = { $umid: "u2", $streams: { new: [], updated: [] } };
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
      return Promise.resolve({ data: {} });
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
  ])("resolves a 200 with a non-object body (%s) as something that is not a commit", async (_n, body, type) => {
    reply = { status: 200, body, type };

    const response: any = await new Connection("http", "127.0.0.1", port).sendTransaction(tx);

    expect(response?.$streams?.new).toBeUndefined();
    expect(response?.$summary?.commit).toBeUndefined();
  });
});
