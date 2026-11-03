import { readFileSync } from "fs";
import { join } from "path";

/**
 * sdk-core's HTTP stack is a runtime dependency of everything built on this
 * SDK. Older axios releases (below 1.20.0) and follow-redirects releases
 * (below 1.16.2) carry known high-severity advisories: request-smuggling and
 * SSRF gadgets, ReDoS, and credential headers that survive a cross-origin
 * redirect.
 *
 * A caret range such as ^1.7.0 lets an install that already has a lockfile stay
 * on a vulnerable release, so the declared floor has to be a patched one. These
 * tests stop the floor being lowered again by accident, and check that this
 * repository's own lockfile resolves to patched releases.
 */
const root = join(__dirname, "..", "..", "..", "..");
const read = (p: string) => JSON.parse(readFileSync(join(root, p), "utf8"));

const FLOORS: { [name: string]: string } = {
  axios: "1.20.0",
  "follow-redirects": "1.16.2",
};

const parts = (v: string): number[] =>
  v.replace(/^[\^~>=v\s]+/, "").split(".").map((n) => parseInt(n, 10));

/** True when version a is the same as or newer than version b */
const atLeast = (a: string, b: string): boolean => {
  const x = parts(a);
  const y = parts(b);
  for (let i = 0; i < 3; i++) {
    if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0);
  }
  return true;
};

describe("sdk-core dependency floors", () => {
  const core = read("packages/core/package.json");
  const lock = read("package-lock.json");

  for (const name of Object.keys(FLOORS)) {
    it(`declares ${name} at ${FLOORS[name]} or newer`, () => {
      const range: string = core.dependencies[name];
      expect(range).toBeDefined();
      expect(atLeast(range, FLOORS[name])).toBe(true);
    });

    it(`resolves ${name} to a patched release in the lockfile`, () => {
      const installed: string = lock.packages[`node_modules/${name}`].version;
      expect(atLeast(installed, FLOORS[name])).toBe(true);
    });
  }

  it("compares versions correctly", () => {
    expect(atLeast("^1.20.0", "1.20.0")).toBe(true);
    expect(atLeast("1.21.3", "1.20.0")).toBe(true);
    expect(atLeast("2.0.0", "1.20.0")).toBe(true);
    expect(atLeast("^1.19.9", "1.20.0")).toBe(false);
    expect(atLeast("^1.7.0", "1.20.0")).toBe(false);
    expect(atLeast("1.16.1", "1.16.2")).toBe(false);
    expect(atLeast("1.16.2", "1.16.2")).toBe(true);
  });
});
