/**
 * baseline.js — continuous-monitoring SURFACE, as code, OSS and free.
 *
 * The premise: a one-shot scan tells you the state today; a *team* wants to
 * know "did anything NEW get worse since we last reviewed this server?"
 * (e.g. a dependency bumped, a new tool added, a transitive MCP server
 * pulled in). That is a diff against a committed baseline — pure, offline,
 * deterministic, no accounts.
 *
 *   1. `mcpaudit <path> --baseline-write baseline.json`
 *        run a scan, write a compact, stable baseline (the set of finding
 *        ids + a summary + a schema version) into the repo.
 *   2. commit `baseline.json`.
 *   3. in CI: `mcpaudit <path> --baseline baseline.json`
 *        re-scan, diff: report NEW findings (ids not in the baseline) and
 *        FIXED findings (baseline ids no longer present). `--fail-on` then
 *        gates only on NEW regressions, so an accepted/triaged finding does
 *        not re-break every build but a freshly-introduced one does.
 *
 * Everything here is a pure function from (findings, baseline JSON) to a
 * diff object + a structured machine record. No file I/O lives in this file
 * (the CLI reads/writes; this module only transforms), no network, no
 * execution of scanned code.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * PAID TIER (operator wires later — NOT in this build, no code here):
 *   The `monitoringRecord()` output below is the exact machine contract a
 *   hosted "watch this server over time / alert on a new critical / fleet
 *   dashboard" tier would consume. This OSS CLI only PRODUCES that record to
 *   stdout/a file and diffs locally. It deliberately contains:
 *     - NO network calls, NO upload, NO scheduler/daemon,
 *     - NO accounts, auth, billing, payment, merchant-of-record, or pricing.
 *   A hosted offering is an operator decision made elsewhere; this file is
 *   only the seam. Do not add money/network/account code here.
 * ───────────────────────────────────────────────────────────────────────────
 */

export const BASELINE_SCHEMA = "mcpaudit-baseline/v1";

/**
 * Build the committed baseline document from a scan report. Stable + sorted
 * so re-writing an unchanged repo produces a byte-identical file (clean
 * diffs, reviewable in PRs).
 *
 * We persist a *fingerprint* per finding rather than the whole finding so the
 * baseline stays small and a snippet/wording tweak in a later mcpaudit
 * version does not spuriously look like a "new" finding — identity is
 * `ruleId|file|line|column` via the existing stable `id`.
 *
 * @param {{root:string,findings:Array,scannedFiles:string[],errors:string[]}} report
 * @returns {object} the baseline document (caller serializes/writes it)
 */
export function buildBaseline(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const entries = findings
    .map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      severity: f.severity,
      file: f.file,
      line: f.line,
      column: f.column,
    }))
    .sort(
      (a, b) =>
        a.file.localeCompare(b.file) ||
        a.line - b.line ||
        String(a.id).localeCompare(String(b.id)),
    );
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const e of entries)
    if (bySeverity[e.severity] !== undefined) bySeverity[e.severity] += 1;
  return {
    schema: BASELINE_SCHEMA,
    tool: "mcpaudit",
    // intentionally NO timestamp/host/user — keeps the file deterministic
    // and the diff reviewable; "when" belongs to git, not this file.
    summary: { total: entries.length, bySeverity },
    findingIds: entries.map((e) => e.id),
    findings: entries,
  };
}

/**
 * Diff a fresh scan against a loaded baseline document.
 *
 * @param {{findings:Array}} report fresh scan
 * @param {object|null} baseline a previously written baseline document (or
 *   null/garbage → everything is treated as NEW, with a note)
 * @returns {{
 *   schemaOk:boolean,
 *   newFindings:Array, fixedFindings:Array, unchangedCount:number,
 *   counts:{ new:number, fixed:number, unchanged:number },
 *   note:string|null
 * }}
 */
export function diffAgainstBaseline(report, baseline) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const schemaOk =
    !!baseline &&
    typeof baseline === "object" &&
    baseline.schema === BASELINE_SCHEMA &&
    Array.isArray(baseline.findingIds);

  const baseIds = new Set(
    schemaOk ? baseline.findingIds : [],
  );
  const baseEntries = new Map(
    schemaOk && Array.isArray(baseline.findings)
      ? baseline.findings.map((e) => [e.id, e])
      : [],
  );

  const currentIds = new Set(findings.map((f) => f.id));
  const newFindings = findings.filter((f) => !baseIds.has(f.id));
  const unchanged = findings.filter((f) => baseIds.has(f.id));
  const fixedFindings = [...baseIds]
    .filter((id) => !currentIds.has(id))
    .map((id) => baseEntries.get(id) || { id })
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));

  let note = null;
  if (!baseline) note = "no baseline supplied — all findings reported as NEW";
  else if (!schemaOk)
    note =
      "baseline file is missing/garbled or from an incompatible schema — all findings reported as NEW (regenerate it with --baseline-write)";

  return {
    schemaOk,
    newFindings,
    fixedFindings,
    unchangedCount: unchanged.length,
    counts: {
      new: newFindings.length,
      fixed: fixedFindings.length,
      unchanged: unchanged.length,
    },
    note,
  };
}

/**
 * The structured, machine-readable monitoring record. This is the stable
 * contract a hosted continuous-monitoring tier (operator, later) would
 * ingest — see the PAID TIER banner at the top of this file. This build only
 * emits it; it never sends it anywhere.
 *
 * @param {{root:string,findings:Array,scannedFiles:string[],errors:string[]}} report
 * @param {ReturnType<typeof diffAgainstBaseline>} diff
 * @returns {object}
 */
export function monitoringRecord(report, diff) {
  const sev = (arr) => {
    const s = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of arr) if (s[f.severity] !== undefined) s[f.severity] += 1;
    return s;
  };
  return {
    schema: "mcpaudit-monitor/v1",
    tool: "mcpaudit",
    target: report.root,
    scannedFileCount: (report.scannedFiles || []).length,
    // The fields a fleet/alerting tier keys on. No identity/PII, no network.
    status:
      diff.counts.new > 0
        ? "regressed"
        : diff.counts.fixed > 0
          ? "improved"
          : "unchanged",
    delta: {
      new: diff.counts.new,
      fixed: diff.counts.fixed,
      unchanged: diff.counts.unchanged,
      newBySeverity: sev(diff.newFindings),
    },
    newFindings: diff.newFindings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      severity: f.severity,
      file: f.file,
      line: f.line,
      column: f.column,
      message: f.message,
    })),
    scanErrors: report.errors || [],
    // PAID TIER seam (operator-only, not implemented here): a hosted tier
    // would POST this exact object to a collector + diff across history /
    // alert. This OSS build only prints it.
    delivery: { mode: "local-only", note: "no network in OSS CLI" },
  };
}
