import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.js"],
    // Hard guarantee: no network, no real API key required in CI. The scan
    // core is pure; the only I/O is reading the local fixture directories.
    env: {},
  },
});
