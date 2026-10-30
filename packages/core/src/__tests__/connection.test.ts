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
