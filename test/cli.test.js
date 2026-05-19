import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { run, parseArgs } from "../bin/mcpaudit.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => join(here, "fixtures", n);

function capture() {
  const out = [];
  const err = [];
  return {
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    stdout: () => out.join("\n"),
    stderr: () => err.join("\n"),
  };
}

describe("parseArgs", () => {
  it("parses target + flags", () => {
    const { opts } = parseArgs(["./x", "--json", "--fail-on", "critical"]);
    expect(opts.target).toBe("./x");
    expect(opts.json).toBe(true);
    expect(opts.failOn).toBe("critical");
  });
  it("supports --fail-on=foo form", () => {
    expect(parseArgs(["p", "--fail-on=medium"]).opts.failOn).toBe("medium");
  });
  it("rejects unknown options", () => {
    expect(parseArgs(["--bogus"]).error).toMatch(/unknown option/);
  });
});

describe("run() exit codes (no network, no key)", () => {
  it("clean fixture → human report, exit 0", async () => {
    const c = capture();
    const code = await run([fx("clean-server")], c.out, c.err);
    expect(code).toBe(0);
    expect(c.stdout()).toMatch(/No findings|0 finding/i);
  });

  it("vulnerable fixture with default --fail-on high → exit 1", async () => {
    const c = capture();
    const code = await run([fx("vulnerable-server")], c.out, c.err);
    expect(code).toBe(1);
    expect(c.stdout()).toMatch(/MCP001/);
    expect(c.stderr()).toMatch(/gate FAILED/);
  });

  it("vulnerable fixture with --fail-on none → exit 0 (still reports)", async () => {
    const c = capture();
    const code = await run(
      [fx("vulnerable-server"), "--fail-on", "none"],
      c.out,
      c.err,
    );
    expect(code).toBe(0);
    expect(c.stdout()).toMatch(/MCP00[1-6]/);
  });

  it("--json emits valid parseable JSON", async () => {
    const c = capture();
    const code = await run([fx("vulnerable-server"), "--json"], c.out, c.err);
    const obj = JSON.parse(c.stdout());
    expect(obj.tool).toBe("mcpaudit");
    expect(obj.summary.total).toBeGreaterThan(0);
    expect(code).toBe(1);
  });

  it("borderline fixture → exit 0, zero findings (no false positive)", async () => {
    const c = capture();
    const code = await run([fx("borderline-server")], c.out, c.err);
    expect(code).toBe(0);
    expect(c.stdout()).toMatch(/No findings/i);
  });

  it("missing target → usage error exit 2", async () => {
    const c = capture();
    expect(await run([], c.out, c.err)).toBe(2);
    expect(c.stderr()).toMatch(/required/);
  });

  it("invalid --fail-on → exit 2", async () => {
    const c = capture();
    expect(await run(["p", "--fail-on", "wat"], c.out, c.err)).toBe(2);
  });

  it("--help → exit 0", async () => {
    const c = capture();
    expect(await run(["--help"], c.out, c.err)).toBe(0);
    expect(c.stdout()).toMatch(/USAGE/);
  });

  it("--sarif emits valid SARIF 2.1.0 and still gates (exit 1 on vuln)", async () => {
    const c = capture();
    const code = await run([fx("vulnerable-server"), "--sarif"], c.out, c.err);
    const obj = JSON.parse(c.stdout());
    expect(obj.version).toBe("2.1.0");
    expect(obj.runs[0].tool.driver.name).toBe("mcpaudit");
    expect(obj.runs[0].results.length).toBeGreaterThan(0);
    expect(code).toBe(1); // gate still applies with --sarif
    // SARIF mode must not print the human "gate FAILED" line into stdout.
    expect(c.stdout()).not.toMatch(/gate FAILED/);
  });

  it("--sarif on a clean tree → empty results, exit 0", async () => {
    const c = capture();
    const code = await run([fx("clean-server"), "--sarif"], c.out, c.err);
    const obj = JSON.parse(c.stdout());
    expect(obj.runs[0].results).toEqual([]);
    expect(code).toBe(0);
  });

  it("parseArgs understands --sarif/--baseline/--baseline-write", () => {
    const { opts } = parseArgs([
      "p",
      "--sarif",
      "--baseline",
      "b.json",
      "--baseline-write=o.json",
    ]);
    expect(opts.sarif).toBe(true);
    expect(opts.baseline).toBe("b.json");
    expect(opts.baselineWrite).toBe("o.json");
  });

  it("a bare package name → stub explains, fails OPEN (exit 0), no network", async () => {
    const c = capture();
    const code = await run(["some-random-mcp-pkg"], c.out, c.err);
    expect(code).toBe(0); // fail-open: never blocks the pipeline
    expect(c.stderr()).toMatch(/local path|not implemented|registry/i);
  });

  it("nonexistent path → diagnostic, fails OPEN (exit 0)", async () => {
    const c = capture();
    const code = await run([fx("nope-not-here")], c.out, c.err);
    expect(code).toBe(0);
    expect(c.stderr()).toMatch(/could not complete|not a directory/i);
  });
});
