import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  LocalDirSource,
  FakeRegistrySource,
  StubRegistrySource,
  resolveTarget,
} from "../src/source.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => join(here, "fixtures", n);

describe("LocalDirSource", () => {
  it("resolves an existing directory to itself", async () => {
    const s = new LocalDirSource();
    const dir = await s.materialize(fx("clean-server"));
    expect(dir).toBe(fx("clean-server"));
  });
});

describe("FakeRegistrySource (tests only — no network)", () => {
  it("maps a package name to a local fixture dir", async () => {
    const s = new FakeRegistrySource({
      "evil-mcp": fx("vulnerable-server"),
    });
    expect(await s.materialize("evil-mcp")).toBe(fx("vulnerable-server"));
  });
  it("throws a clear error for an unknown package", async () => {
    const s = new FakeRegistrySource({});
    await expect(s.materialize("nope")).rejects.toThrow(/unknown package/i);
  });
});

describe("StubRegistrySource (the shipped default for named packages)", () => {
  it("does NOT hit the network and explains it needs operator wiring", async () => {
    const s = new StubRegistrySource();
    await expect(s.materialize("left-pad")).rejects.toThrow(
      /not implemented|operator|registry|path/i,
    );
  });
});

describe("resolveTarget", () => {
  it("treats an existing path as a LocalDirSource target", () => {
    const t = resolveTarget(fx("clean-server"));
    expect(t.kind).toBe("path");
  });
  it("treats a non-path token as a package name", () => {
    const t = resolveTarget("@scope/some-mcp-server");
    expect(t.kind).toBe("package");
  });
});
