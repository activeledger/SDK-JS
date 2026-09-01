// sdk-web needs its own Jest config, separate from the root jestconfig.json
// used by sdk-core/sdk-node - this package (and its @noble/curves /
// @scure/bip39 dependencies) is ESM-only, and ts-jest's default CommonJS
// preset can't `require()` an ESM-only package. Run with:
//   NODE_OPTIONS=--experimental-vm-modules npx jest --config jest.config.mjs
// (see the "test" script in this package's package.json).
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    // Source imports use explicit .js extensions (required under
    // "moduleResolution": "nodenext") even though the actual files are
    // .ts - strip the extension so Jest's resolver finds the real file.
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    // packages/web/tsconfig.json sets "types": [] for the real build (to
    // avoid an ambient @types/node conflict that broke tsc against
    // @noble/curves' modern type-checking needs) - test files need Node's
    // types back (crypto, etc., for constructing cross-platform fixtures),
    // so it's restored just for this transform.
    "^.+\\.tsx?$": ["ts-jest", { useESM: true, tsconfig: { types: ["node", "jest"] } }],
  },
};
