/**
 * sarif.test.js — the SARIF v2.1.0 output must be schema-correct enough that
 * `github/codeql-action/upload-sarif` accepts it. We assert the structural
 * invariants GitHub code scanning requires (no network, pure function).
 */
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyzeProject } from "../src/analyze.js";
import { formatSarif } from "../src/format.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => join(here, "fixtures", n);

describe("formatSarif", () => {
  const report = analyzeProject(fx("vulnerable-server"));
  const sarif = JSON.parse(formatSarif(report, "9.9.9"));

  it("declares SARIF 2.1.0 and the canonical $schema", () => {
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toMatch(/sarif-schema-2\.1\.0\.json$/);
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs).toHaveLength(1);
  });

  it("populates tool.driver with name, version and a rules array", () => {
    const d = sarif.runs[0].tool.driver;
    expect(d.name).toBe("mcpaudit");
    expect(d.version).toBe("9.9.9");
    expect(Array.isArray(d.rules)).toBe(true);
    expect(d.rules.length).toBeGreaterThan(0);
    for (const r of d.rules) {
      expect(typeof r.id).toBe("string");
      expect(r.shortDescription.text).toBeTypeOf("string");
      expect(["error", "warning", "note", "none"]).toContain(
        r.defaultConfiguration.level,
      );
      // GitHub code-scanning severity ranking property.
      expect(r.properties["security-severity"]).toMatch(/^\d+(\.\d+)?$/);
    }
  });

  it("emits one result per finding with a valid physicalLocation", () => {
    const results = sarif.runs[0].results;
    expect(results.length).toBe(report.findings.length);
    for (const res of results) {
      expect(typeof res.ruleId).toBe("string");
      expect(Number.isInteger(res.ruleIndex)).toBe(true);
      expect(["error", "warning", "note", "none"]).toContain(res.level);
      expect(res.message.text.length).toBeGreaterThan(0);
      const loc = res.locations[0].physicalLocation;
      // SARIF artifactLocation.uri must be forward-slash, no leading "./".
      expect(loc.artifactLocation.uri).not.toMatch(/^\.\//);
      expect(loc.artifactLocation.uri).not.toMatch(/\\/);
      expect(loc.region.startLine).toBeGreaterThanOrEqual(1);
      expect(loc.region.startColumn).toBeGreaterThanOrEqual(1);
      // Stable finding id is carried as a partial fingerprint for dedupe.
      expect(res.partialFingerprints.mcpauditFindingId).toMatch(/^MCP\d+-/);
    }
  });

  it("ruleIndex of every result points at a real rule in driver.rules", () => {
    const rules = sarif.runs[0].tool.driver.rules;
    for (const res of sarif.runs[0].results) {
      expect(rules[res.ruleIndex].id).toBe(res.ruleId);
    }
  });

  it("is deterministic (same report → byte-identical SARIF)", () => {
    const a = formatSarif(report, "1.0.0");
    const b = formatSarif(report, "1.0.0");
    expect(a).toBe(b);
  });

  it("produces a valid (empty-results) SARIF for a clean scan", () => {
    const clean = JSON.parse(formatSarif(analyzeProject(fx("clean-server"))));
    expect(clean.runs[0].results).toEqual([]);
    expect(clean.runs[0].invocations[0].executionSuccessful).toBe(true);
  });

  it("does not emit any `undefined` JSON values", () => {
    const raw = formatSarif(report);
    expect(raw).not.toMatch(/:\s*undefined/);
  });
});
