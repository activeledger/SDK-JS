import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { KeyHandler } from "../key";

describe("KeyHandler.exportKey / importKey", () => {
  const keys = new KeyHandler();
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sdk-keys-"));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("round-trips a key through a file", async () => {
    const key = await keys.generateKey("alice");
    await keys.exportKey(key, dir);

    expect(await keys.importKey(path.join(dir, "alice.json"))).toEqual(key);
  });

  it("round-trips a post-quantum key with its type and identity", async () => {
    const key = await keys.generateKey("pq", false, "falcon-512" as any);
    key.identity = "stream-1";
    await keys.exportKey(key, dir);

    const back = await keys.importKey(path.join(dir, "pq.json"));
    expect(back.type).toBe(key.type);
    expect(back.identity).toBe("stream-1");
    expect(back.key).toEqual(key.key);
  });

  it("strips a trailing slash from the location", async () => {
    const key = await keys.generateKey("alice");
    await keys.exportKey(key, dir + "/");

    expect(fs.existsSync(path.join(dir, "alice.json"))).toBe(true);
  });

  it("uses options.name for the file name", async () => {
    const key = await keys.generateKey("alice");
    await keys.exportKey(key, { location: dir, name: "backup" });

    expect(fs.existsSync(path.join(dir, "backup.json"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "alice.json"))).toBe(false);
  });

  it("refuses to overwrite an existing file, leaving it intact", async () => {
    const first = await keys.generateKey("alice");
    const second = await keys.generateKey("alice");
    await keys.exportKey(first, dir);

    await expect(keys.exportKey(second, dir)).rejects.toMatch("File already exists");
    expect(await keys.importKey(path.join(dir, "alice.json"))).toEqual(first);
  });

  it("overwrites when asked to", async () => {
    const first = await keys.generateKey("alice");
    const second = await keys.generateKey("alice");
    await keys.exportKey(first, dir);
    await keys.exportKey(second, dir, false, true);

    expect(await keys.importKey(path.join(dir, "alice.json"))).toEqual(second);
  });

  it("rejects when the location does not exist and createDir is off", async () => {
    const key = await keys.generateKey("alice");
    await expect(keys.exportKey(key, path.join(dir, "missing"))).rejects.toBe("Unable to find location");
  });

  it("creates the directory tree when createDir is set", async () => {
    const key = await keys.generateKey("alice");
    const nested = path.join(dir, "a", "b");
    await keys.exportKey(key, nested, true);

    expect(await keys.importKey(path.join(nested, "alice.json"))).toEqual(key);
  });

  it("importKey rejects for a missing file", async () => {
    await expect(keys.importKey(path.join(dir, "nope.json"))).rejects.toBe("File not found.");
  });

  it("an imported key still signs", async () => {
    const { PayloadHandler } = require("../payload");
    const key = await keys.generateKey("alice");
    await keys.exportKey(key, dir);
    const back = await keys.importKey(path.join(dir, "alice.json"));
    const payload = new PayloadHandler();

    const sig = payload.sign({ a: 1 }, back);
    expect(payload.verify({ a: 1 }, sig, key.key.pub.pkcs8pem, key.type)).toBe(true);
    expect(payload.verify({ a: 2 }, sig, key.key.pub.pkcs8pem, key.type)).toBe(false);
  });
});
