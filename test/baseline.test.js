/**
 * baseline.test.js — the continuous-monitoring SURFACE (free/OSS scaffold).
 * Pure functions + a CLI integration round-trip. No network, no accounts, no
 * money code is exercised because none exists (PAID TIER is operator-only).
 */
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  buildBaseline,
  diffAgainstBaseline,
  monitoringRecord,
  BASELINE_SCHEMA,
} from "../src/baseline.js";
import { analyzeProject } from "../src/analyze.js";
import { run } from "../bin/mcpaudit.js";

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

describe("buildBaseline / diffAgainstBaseline (pure)", () => {
  const vuln = analyzeProject(fx("vulnerable-server"));
  const clean = analyzeProject(fx("clean-server"));

  it("a baseline of a scan diffed against itself yields zero NEW", () => {
    const base = buildBaseline(vuln);
    expect(base.schema).toBe(BASELINE_SCHEMA);
    expect(base.summary.total).toBe(vuln.findings.length);
    const d = diffAgainstBaseline(vuln, base);
    expect(d.counts.new).toBe(0);
    expect(d.counts.fixed).toBe(0);
    expect(d.counts.unchanged).toBe(vuln.findings.length);
    expect(d.schemaOk).toBe(true);
  });

  it("is deterministic — buildBaseline of an unchanged scan is stable", () => {
    expect(JSON.stringify(buildBaseline(vuln))).toBe(
      JSON.stringify(buildBaseline(vuln)),
    );
    // and contains no timestamp/host/user (reviewable, git owns "when")
    const s = JSON.stringify(buildBaseline(vuln));
    expect(s).not.toMatch(/timestamp|generatedAt|hostname|"user"/i);
  });

  it("reports ALL findings as NEW when the clean baseline predates them", () => {
    const cleanBase = buildBaseline(clean); // zero findings
    const d = diffAgainstBaseline(vuln, cleanBase);
    expect(d.counts.new).toBe(vuln.findings.length);
    expect(d.counts.fixed).toBe(0);
  });

  it("reports FIXED when a baseline finding is no longer present", () => {
    const vulnBase = buildBaseline(vuln);
    const d = diffAgainstBaseline(clean, vulnBase); // regressions resolved
    expect(d.counts.new).toBe(0);
    expect(d.counts.fixed).toBe(vuln.findings.length);
    expect(d.counts.unchanged).toBe(0);
  });

  it("treats a missing/garbled baseline as all-NEW with a note (fails safe)", () => {
    const d1 = diffAgainstBaseline(vuln, null);
    expect(d1.schemaOk).toBe(false);
    expect(d1.counts.new).toBe(vuln.findings.length);
    expect(d1.note).toMatch(/no baseline/i);

    const d2 = diffAgainstBaseline(vuln, { schema: "something-else" });
    expect(d2.schemaOk).toBe(false);
    expect(d2.note).toMatch(/incompatible|garbled|regenerate/i);
  });

  it("monitoringRecord is a local-only structured record (no delivery/auth keys)", () => {
    const rec = monitoringRecord(vuln, diffAgainstBaseline(vuln, buildBaseline(clean)));
    expect(rec.schema).toBe("mcpaudit-monitor/v1");
    expect(rec.status).toBe("regressed");
    expect(rec.delta.new).toBe(vuln.findings.length);
    // The PAID-TIER seam must be inert in the OSS build: the only delivery
    // descriptor is "local-only" and there is NO auth/account/billing/upload
    // KEY in the record envelope (finding *messages* legitimately quote
    // scanned URLs/"token" — that is correct reporting, not exfiltration).
    expect(rec.delivery).toEqual({
      mode: "local-only",
      note: "no network in OSS CLI",
    });
    const envelopeKeys = Object.keys(rec);
    for (const k of envelopeKeys) {
      expect(k).not.toMatch(/token|apiKey|account|billing|auth|upload|endpoint/i);
    }
  });
});

describe("CLI baseline round-trip (no network, no key)", () => {
  it("--baseline-write then --baseline gates ONLY on new regressions", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mcpaudit-bl-"));
    const blFile = join(tmp, "baseline.json");
    try {
      // 1. accept current (vulnerable) state into a baseline.
      const c1 = capture();
      const code1 = await run(
        [fx("vulnerable-server"), "--baseline-write", blFile],
        c1.out,
        c1.err,
      );
      expect(code1).toBe(0);
      const doc = JSON.parse(readFileSync(blFile, "utf8"));
      expect(doc.schema).toBe(BASELINE_SCHEMA);
      expect(doc.findingIds.length).toBeGreaterThan(0);

      // 2. re-scan SAME tree against that baseline → no NEW → exit 0 even
      //    though there are critical findings (they are accepted/triaged).
      const c2 = capture();
      const code2 = await run(
        [fx("vulnerable-server"), "--baseline", blFile, "--fail-on", "critical"],
        c2.out,
        c2.err,
      );
      expect(code2).toBe(0);
      expect(c2.stdout()).toMatch(/NEW: 0/);

      // 3. a DIFFERENT tree (clean) against the vuln baseline → everything
      //    fixed, still exit 0, FIXED reported.
      const c3 = capture();
      const code3 = await run(
        [fx("clean-server"), "--baseline", blFile, "--fail-on", "critical"],
        c3.out,
        c3.err,
      );
      expect(code3).toBe(0);
      expect(c3.stdout()).toMatch(/FIXED:/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("--baseline against a clean baseline → NEW regressions DO gate (exit 1)", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mcpaudit-bl2-"));
    const blFile = join(tmp, "baseline.json");
    try {
      // baseline captured from the CLEAN tree (zero findings)…
      await run([fx("clean-server"), "--baseline-write", blFile], () => {}, () => {});
      // …then scan the VULNERABLE tree against it: every finding is NEW, so
      // the gate must fail.
      const c = capture();
      const code = await run(
        [fx("vulnerable-server"), "--baseline", blFile, "--fail-on", "high"],
        c.out,
        c.err,
      );
      expect(code).toBe(1);
      expect(c.stderr()).toMatch(/NEW finding\(s\).*baseline/i);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("--monitor-json with --baseline emits the machine record, exit reflects gate", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "mcpaudit-bl3-"));
    const blFile = join(tmp, "baseline.json");
    try {
      await run([fx("clean-server"), "--baseline-write", blFile], () => {}, () => {});
      const c = capture();
      const code = await run(
        [
          fx("vulnerable-server"),
          "--baseline",
          blFile,
          "--monitor-json",
          "--fail-on",
          "none",
        ],
        c.out,
        c.err,
      );
      const rec = JSON.parse(c.stdout());
      expect(rec.schema).toBe("mcpaudit-monitor/v1");
      expect(rec.status).toBe("regressed");
      expect(rec.delivery.mode).toBe("local-only");
      expect(code).toBe(0); // fail-on none
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
