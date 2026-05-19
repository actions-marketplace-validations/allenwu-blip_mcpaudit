#!/usr/bin/env node
/**
 * src/action.js — the thin GitHub Action wrapper.
 *
 * It is deliberately tiny: map Action inputs → the same pure scan the CLI
 * uses, print the human report into the job log, emit GitHub annotations for
 * each finding, set outputs, and use the gate as the step exit code.
 *
 * No automated test here (it is I/O glue around env + stdout). Every unit of
 * logic it calls is covered by the pure-module + CLI tests. Like a good
 * linter it NEVER hard-crashes the workflow: an internal failure is surfaced
 * loudly and the step exits 0 (use `fail-on` + a required check to enforce).
 */

import { appendFileSync, writeFileSync, readFileSync } from "node:fs";
import { analyzeProject } from "./analyze.js";
import { gate } from "./rules.js";
import { formatHuman, formatJson, formatSarif } from "./format.js";
import { buildBaseline, diffAgainstBaseline } from "./baseline.js";
import { LocalDirSource, StubRegistrySource, resolveTarget } from "./source.js";

const ACTION_VERSION = "0.1.0";

function input(name, def = "") {
  const key = `INPUT_${name.toUpperCase().replace(/[ -]/g, "_")}`;
  const v = process.env[key];
  return v === undefined || v === "" ? def : v;
}
function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  if (f) appendFileSync(f, `${name}=${String(value).replace(/\n/g, " ")}\n`);
  console.log(`mcpaudit: ${name}=${value}`);
}
function info(msg) {
  console.log(`mcpaudit: ${msg}`);
}
// GitHub annotation (shows inline on the PR / in the checks UI).
function annotate(level, f) {
  const sev = level === "critical" || level === "high" ? "error" : "warning";
  const props = `file=${f.file},line=${f.line},col=${f.column},title=${f.ruleId} (${f.severity})`;
  console.log(`::${sev} ${props}::${f.message} — fix: ${f.remediation}`);
}

async function main() {
  const target = input("path", ".");
  const failOn = input("fail-on", "high").toLowerCase();
  const asJson = String(input("json", "false")).toLowerCase() === "true";
  const asSarif = String(input("sarif", "false")).toLowerCase() === "true";
  const sarifFile = input("sarif-file", "mcpaudit.sarif");
  const baselineFile = input("baseline", "");

  try {
    const t = resolveTarget(target);
    let dir;
    if (t.kind === "path") {
      dir = await new LocalDirSource().materialize(t.value);
    } else {
      dir = await new StubRegistrySource().materialize(t.value);
    }

    const report = analyzeProject(dir);

    // Optional baseline diff: gate only on NEW findings (regressions).
    let diff = null;
    if (baselineFile) {
      let baselineDoc = null;
      try {
        baselineDoc = JSON.parse(readFileSync(baselineFile, "utf8"));
      } catch {
        baselineDoc = null;
      }
      diff = diffAgainstBaseline(report, baselineDoc);
    }

    if (asJson) console.log(formatJson(report).replace(/\n$/, ""));
    else console.log(formatHuman(report, { color: false }));

    // SARIF: write a file the workflow uploads with upload-sarif. We never
    // throw if the write fails — surface it and continue (fail-open ethos).
    if (asSarif) {
      try {
        writeFileSync(sarifFile, formatSarif(report, ACTION_VERSION));
        setOutput("sarif-file", sarifFile);
        info(`wrote SARIF to ${sarifFile}`);
      } catch (e) {
        console.log(
          `::warning title=mcpaudit::could not write SARIF (${e && e.message ? e.message : e}); continuing.`,
        );
      }
    }

    for (const f of report.findings) annotate(f.severity, f);

    if (diff) {
      info(
        `baseline diff — NEW: ${diff.counts.new} · FIXED: ${diff.counts.fixed} · unchanged: ${diff.counts.unchanged}` +
          (diff.note ? ` (${diff.note})` : ""),
      );
      setOutput("new", diff.counts.new);
      setOutput("fixed", diff.counts.fixed);
    }

    const s = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of report.findings) if (s[f.severity] !== undefined) s[f.severity]++;
    setOutput("total", report.findings.length);
    setOutput("critical", s.critical);
    setOutput("high", s.high);
    setOutput("medium", s.medium);
    setOutput("low", s.low);

    // With a baseline, gate on NEW findings only; otherwise on all findings.
    const gateSet = diff ? diff.newFindings : report.findings;
    const failed = gate(gateSet, failOn);
    setOutput("gate", failed ? "fail" : "pass");
    if (failed) {
      info(
        diff
          ? `gate FAILED — NEW finding(s) at or above "${failOn}" since the baseline.`
          : `gate FAILED — finding(s) at or above "${failOn}".`,
      );
      process.exitCode = 1;
    } else {
      info(`gate passed (fail-on=${failOn}${diff ? ", baseline-diff" : ""}).`);
    }
  } catch (e) {
    // Fail OPEN, loudly. A scanner outage must not block every PR.
    console.log(
      `::warning title=mcpaudit::scan could not complete (${e && e.message ? e.message : e}); failing open (exit 0). Use 'fail-on' with a required check to enforce.`,
    );
    info("scan failed open (exit 0).");
  }
}

main().catch((e) => {
  console.log(`mcpaudit: unexpected error (non-fatal): ${e && e.message ? e.message : e}`);
});
