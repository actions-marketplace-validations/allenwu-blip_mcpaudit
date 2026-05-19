import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyzeProject } from "../src/analyze.js";
import { gate, SEVERITY_ORDER } from "../src/rules.js";
import { formatHuman, formatJson } from "../src/format.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => join(here, "fixtures", n);

describe("analyzeProject on fixtures (offline, no network)", () => {
  it("clean-server produces ZERO findings", () => {
    const r = analyzeProject(fx("clean-server"));
    expect(r.errors).toEqual([]);
    expect(r.findings, JSON.stringify(r.findings, null, 2)).toHaveLength(0);
    expect(r.scannedFiles.length).toBeGreaterThan(0);
  });

  it("vulnerable-server fires every rule with correct severity", () => {
    const r = analyzeProject(fx("vulnerable-server"));
    const rules = new Set(r.findings.map((f) => f.ruleId));
    for (const id of [
      "MCP001",
      "MCP002",
      "MCP003",
      "MCP004",
      "MCP005",
      "MCP006",
    ]) {
      expect(rules.has(id), `expected ${id} to fire`).toBe(true);
    }
    const sev = (id) =>
      r.findings.find((f) => f.ruleId === id).severity;
    expect(sev("MCP001")).toBe("critical");
    expect(sev("MCP002")).toBe("high");
    expect(sev("MCP003")).toBe("high");
    expect(sev("MCP005")).toBe("high");
    expect(sev("MCP004")).toBe("medium");
    expect(sev("MCP006")).toBe("medium");

    // file:line must point into the right file.
    const inj = r.findings.find((f) => f.ruleId === "MCP001");
    expect(inj.file).toMatch(/index\.js$/);
    expect(inj.line).toBeGreaterThan(0);
  });

  it("borderline-server produces ZERO findings (false-positive guard)", () => {
    const r = analyzeProject(fx("borderline-server"));
    expect(
      r.findings,
      "borderline must not false-positive:\n" +
        JSON.stringify(r.findings, null, 2),
    ).toHaveLength(0);
  });

  it("returns a diagnostic (not a throw) for a missing directory", () => {
    const r = analyzeProject(fx("does-not-exist"));
    expect(r.errors.length).toBeGreaterThan(0);
    expect(Array.isArray(r.findings)).toBe(true);
  });
});

describe("gate()", () => {
  const mk = (sev) => ({ severity: sev });
  it("orders severities", () => {
    expect(SEVERITY_ORDER.critical).toBeGreaterThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeGreaterThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeGreaterThan(SEVERITY_ORDER.low);
  });
  it("fails when a finding meets/exceeds the gate", () => {
    expect(gate([mk("high")], "high")).toBe(true);
    expect(gate([mk("critical")], "high")).toBe(true);
  });
  it("passes when below the gate", () => {
    expect(gate([mk("medium"), mk("low")], "high")).toBe(false);
  });
  it("'none' never gates", () => {
    expect(gate([mk("critical")], "none")).toBe(false);
  });
  it("empty findings never gate", () => {
    expect(gate([], "low")).toBe(false);
  });
});

describe("formatters", () => {
  const report = {
    root: "/tmp/x",
    findings: [
      {
        id: "MCP001-1",
        ruleId: "MCP001",
        severity: "critical",
        file: "src/i.js",
        line: 3,
        column: 5,
        message: "command injection via exec()",
        remediation: "use execFile with an argv array",
        snippet: "exec(`ping ${host}`)",
      },
    ],
    scannedFiles: ["src/i.js"],
    errors: [],
  };

  it("formatJson is valid parseable JSON with a schema version + summary", () => {
    const obj = JSON.parse(formatJson(report));
    expect(obj.schema).toBeTypeOf("string");
    expect(obj.summary.total).toBe(1);
    expect(obj.summary.bySeverity.critical).toBe(1);
    expect(obj.findings[0].ruleId).toBe("MCP001");
  });

  it("formatHuman includes severity, location, message and remediation", () => {
    const s = formatHuman(report);
    expect(s).toMatch(/MCP001/);
    expect(s).toMatch(/critical/i);
    expect(s).toMatch(/src\/i\.js:3/);
    expect(s).toMatch(/execFile/);
  });

  it("formatHuman reports a clean bill of health on zero findings", () => {
    const s = formatHuman({ ...report, findings: [] });
    expect(s).toMatch(/no findings|clean/i);
  });
});
