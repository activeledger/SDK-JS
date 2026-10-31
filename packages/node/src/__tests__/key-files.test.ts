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

  it("rejects when createDir cannot make the directory, and writes nothing", async () => {
    const key = await keys.generateKey("alice");
    const blocker = path.join(dir, "blocker");
    fs.writeFileSync(blocker, "a file where a directory is needed");

    await expect(keys.exportKey(key, path.join(blocker, "keys"), true)).rejects.toMatchObject({ code: "ENOTDIR" });
    expect(fs.readdirSync(dir)).toEqual(["blocker"]);
  });

  it("importKey rejects, rather than hanging, when the path is a directory", async () => {
    await expect(keys.importKey(dir)).rejects.toMatchObject({ code: "EISDIR" });
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

  describe("importKey validation", () => {
    const write = (value: unknown): string => {
      const file = path.join(dir, "bad.json");
      fs.writeFileSync(file, typeof value === "string" ? value : JSON.stringify(value));
      return file;
    };
    const mutate = (key: any, f: (k: any) => void) => {
      const copy = JSON.parse(JSON.stringify(key));
      f(copy);
      return copy;
    };

    it.each(["secp256k1", "ml-dsa-65", "falcon-512"])("accepts a freshly generated %s key", async (type) => {
      const key = await keys.generateKey("k", false, type as any);
      await keys.exportKey(key, dir);
      expect(await keys.importKey(path.join(dir, "k.json"))).toEqual(key);
    });

    it("accepts compressed and uncompressed secp256k1 public keys, with or without 0x", async () => {
      for (const compressed of [true, false]) {
        const key = await keys.generateKey("k", compressed);
        await expect(keys.importKey(write(key))).resolves.toEqual(key);
        const bare = mutate(key, (k) => {
          k.key.prv.pkcs8pem = k.key.prv.pkcs8pem.slice(2);
          k.key.pub.pkcs8pem = k.key.pub.pkcs8pem.slice(2);
        });
        await expect(keys.importKey(write(bare))).resolves.toEqual(bare);
      }
    });

    it("rejects a file that is not JSON, or not an object", async () => {
      await expect(keys.importKey(write("not json"))).rejects.toThrow();
      await expect(keys.importKey(write("null"))).rejects.toThrow("expected an object");
      await expect(keys.importKey(write("[]"))).rejects.toThrow("Invalid key");
    });

    it("rejects an unknown or missing type", async () => {
      const key = await keys.generateKey("k");
      await expect(keys.importKey(write(mutate(key, (k) => (k.type = "rsa"))))).rejects.toThrow('unsupported type "rsa"');
      await expect(keys.importKey(write(mutate(key, (k) => delete k.type)))).rejects.toThrow("unsupported type");
    });

    it("rejects missing or non-string key material", async () => {
      const key = await keys.generateKey("k");
      await expect(keys.importKey(write(mutate(key, (k) => delete k.key.prv)))).rejects.toThrow("must be strings");
      await expect(keys.importKey(write(mutate(key, (k) => (k.key.pub.pkcs8pem = 5))))).rejects.toThrow("must be strings");
      await expect(keys.importKey(write(mutate(key, (k) => (k.name = ""))))).rejects.toThrow("name");
    });

    it.each([
      ["non-hex characters", (k: any) => (k.key.prv.pkcs8pem = "0x" + "zz".repeat(32))],
      ["an odd number of digits", (k: any) => (k.key.prv.pkcs8pem = "0x" + "1".repeat(63))],
      ["a short private key", (k: any) => (k.key.prv.pkcs8pem = "0x" + "11".repeat(31))],
      ["a long private key", (k: any) => (k.key.prv.pkcs8pem = "0x" + "11".repeat(33))],
      ["a zero scalar", (k: any) => (k.key.prv.pkcs8pem = "0x" + "00".repeat(32))],
      ["a scalar equal to n", (k: any) => (k.key.prv.pkcs8pem = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")],
      ["a public key of the wrong length", (k: any) => (k.key.pub.pkcs8pem = "0x02" + "11".repeat(10))],
      ["a public key with a bad prefix", (k: any) => (k.key.pub.pkcs8pem = "0x05" + k.key.pub.pkcs8pem.slice(4))],
    ])("rejects secp256k1 with %s", async (_n, f) => {
      const key = await keys.generateKey("k", true);
      await expect(keys.importKey(write(mutate(key, f)))).rejects.toThrow("Invalid secp256k1 key");
    });

    it("rejects a secp256k1 private key paired with someone else's public key", async () => {
      const a = await keys.generateKey("a", true);
      const b = await keys.generateKey("b", true);
      const mixed = mutate(a, (k) => (k.key.pub.pkcs8pem = b.key.pub.pkcs8pem));
      await expect(keys.importKey(write(mixed))).rejects.toThrow("do not belong together");
    });

    it.each(["ml-dsa-65", "falcon-512"])("rejects a %s key with mismatched halves", async (type) => {
      const a = await keys.generateKey("a", false, type as any);
      const b = await keys.generateKey("b", false, type as any);
      const mixed = mutate(a, (k) => (k.key.pub.pkcs8pem = b.key.pub.pkcs8pem));
      await expect(keys.importKey(write(mixed))).rejects.toThrow("do not belong together");
    });

    it.each(["ml-dsa-65", "falcon-512"])("rejects a %s key with bad encoding or length", async (type) => {
      const a = await keys.generateKey("a", false, type as any);
      await expect(keys.importKey(write(mutate(a, (k) => (k.key.prv.pkcs8pem = "!!!"))))).rejects.toThrow("base64");
      await expect(keys.importKey(write(mutate(a, (k) => (k.key.pub.pkcs8pem = k.key.pub.pkcs8pem.slice(8)))))).rejects.toThrow(
        /base64|bytes/
      );
      await expect(keys.importKey(write(mutate(a, (k) => (k.key.prv.pkcs8pem = "AAAA"))))).rejects.toThrow("private key must be");
    });

    it("rejects a post-quantum key whose type does not match its material", async () => {
      const a = await keys.generateKey("a", false, "ml-dsa-65" as any);
      await expect(keys.importKey(write(mutate(a, (k) => (k.type = "falcon-512"))))).rejects.toThrow("Invalid falcon-512 key");
      await expect(keys.importKey(write(mutate(a, (k) => (k.type = "secp256k1"))))).rejects.toThrow("Invalid secp256k1 key");
    });
  });
});
