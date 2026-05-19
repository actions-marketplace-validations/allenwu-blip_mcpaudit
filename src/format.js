/**
 * format.js — pure presentation. No I/O. Two consumers:
 *   - formatHuman: a developer reading the terminal before `npx`-ing a server
 *   - formatJson:  CI / tooling (stable schema, summary counts)
 */

const SEV_LABEL = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};
const SEV_GLYPH = {
  critical: "✖",
  high: "✖",
  medium: "▲",
  low: "•",
};

export const JSON_SCHEMA_VERSION = "mcpaudit/v1";

function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byRule = {};
  for (const f of findings) {
    if (bySeverity[f.severity] !== undefined) bySeverity[f.severity] += 1;
    byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;
  }
  return { total: findings.length, bySeverity, byRule };
}

/**
 * @param {{root:string,findings:Array,scannedFiles:string[],errors:string[]}} report
 * @returns {string} JSON (machine/CI)
 */
export function formatJson(report) {
  return (
    JSON.stringify(
      {
        schema: JSON_SCHEMA_VERSION,
        tool: "mcpaudit",
        root: report.root,
        scannedFileCount: report.scannedFiles.length,
        summary: summarize(report.findings),
        findings: report.findings,
        errors: report.errors,
      },
      null,
      2,
    ) + "\n"
  );
}

// SARIF severity mapping. SARIF `level` is one of error|warning|note|none;
// the fine-grained severity is carried in `properties.security-severity`
// (0.0–10.0, GitHub code-scanning convention) and the rule's own severity.
const SARIF_LEVEL = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};
const SECURITY_SEVERITY = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "2.0",
};

// One-line rule descriptions for the SARIF `rules` array (helpUri-free; the
// scanner is self-contained). Keep in sync with README "What it detects".
const RULE_HELP = {
  MCP001: "Command injection via child_process with a non-literal command.",
  MCP002: "Environment/credential exfiltration into LLM-visible output.",
  MCP003: "Over-broad filesystem scope declared in the MCP manifest.",
  MCP004: "Unrestricted/wildcard tool or permission scope.",
  MCP005: "Dangerous dynamic code execution (eval/Function/vm) of non-literal.",
  MCP006: "Unpinned remote code execution (curl|sh, npx @latest, uvx).",
  MCP007: "Prototype-pollution sink (dynamic key assignment / unsafe merge).",
  MCP008: "SSRF-able outbound request with an attacker-influenced URL.",
  MCP009: "Hardcoded credential in source (string literal / tool schema).",
  MCP010: "Path traversal in a filesystem tool (non-literal, unsanitised path).",
  MCP011: "Unsafe deserialization of non-literal data (unserialize/yaml.load).",
  MCP012: "Dangerous npm lifecycle script (network-into-shell install hook).",
  MCP013: "Credential committed in a manifest (env block / config).",
  MCP014: "Risky declared dependency (non-registry source / typosquat shape).",
};

/**
 * SARIF v2.1.0 — the format `github/codeql-action/upload-sarif` ingests so
 * findings render in the GitHub "Code scanning" tab. Pure; deterministic
 * field order. We populate `partialFingerprints.mcpauditFindingId` with the
 * stable finding id so GitHub can de-dupe/track a finding across runs.
 *
 * @param {{root:string,findings:Array,scannedFiles:string[],errors:string[]}} report
 * @param {string} [version]
 * @returns {string} SARIF JSON
 */
export function formatSarif(report, version = "0.1.0") {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const seenRules = new Map();
  for (const f of findings) {
    if (!seenRules.has(f.ruleId)) {
      seenRules.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleId,
        shortDescription: { text: RULE_HELP[f.ruleId] || f.ruleId },
        fullDescription: { text: RULE_HELP[f.ruleId] || f.ruleId },
        defaultConfiguration: {
          level: SARIF_LEVEL[f.severity] || "warning",
        },
        properties: {
          tags: ["security", "mcp"],
          "security-severity": SECURITY_SEVERITY[f.severity] || "5.0",
        },
      });
    }
  }
  const rules = [...seenRules.values()];
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
    level: SARIF_LEVEL[f.severity] || "warning",
    message: { text: `${f.message} (fix: ${f.remediation})` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            // SARIF wants forward-slash, repo-relative, no leading "./".
            uri: String(f.file).replace(/\\/g, "/").replace(/^\.\//, ""),
            uriBaseId: "SRCROOT",
          },
          region: {
            startLine: Math.max(1, Number(f.line) || 1),
            startColumn: Math.max(1, Number(f.column) || 1),
            snippet: f.snippet ? { text: f.snippet } : undefined,
          },
        },
      },
    ],
    partialFingerprints: {
      mcpauditFindingId: f.id,
    },
    properties: { severity: f.severity },
  }));

  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcpaudit",
            informationUri:
              "https://github.com/portfolio-foundry/mcp-audit-cli",
            version,
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            toolExecutionNotifications: (report.errors || []).map((e) => ({
              level: "warning",
              message: { text: String(e) },
            })),
          },
        ],
        columnKind: "utf16CodeUnits",
      },
    ],
  };
  // Drop `undefined` snippet keys for strict validators.
  return JSON.stringify(sarif, (_k, v) => (v === undefined ? undefined : v), 2) + "\n";
}

/**
 * @param {object} report
 * @param {{color?:boolean}} [opts]
 * @returns {string} a human report
 */
export function formatHuman(report, opts = {}) {
  const useColor = opts.color === true;
  const c = (code, s) => (useColor ? `[${code}m${s}[0m` : s);
  const sevColor = {
    critical: (s) => c("1;31", s),
    high: (s) => c("31", s),
    medium: (s) => c("33", s),
    low: (s) => c("36", s),
  };

  const lines = [];
  lines.push(`mcpaudit — static MCP server security scan`);
  lines.push(`target: ${report.root}`);
  lines.push(
    `scanned ${report.scannedFiles.length} file(s); ${report.findings.length} finding(s)`,
  );
  lines.push("");

  if (report.findings.length === 0) {
    lines.push(
      "No findings. (Static analysis is not a guarantee — review the server's tools and scope yourself; see Limitations in the README.)",
    );
  } else {
    const s = summarize(report.findings).bySeverity;
    lines.push(
      `summary: ${s.critical} critical · ${s.high} high · ${s.medium} medium · ${s.low} low`,
    );
    lines.push("");
    for (const f of report.findings) {
      const g = SEV_GLYPH[f.severity] || "•";
      const tag = sevColor[f.severity]
        ? sevColor[f.severity](SEV_LABEL[f.severity])
        : f.severity.toUpperCase();
      lines.push(`${g} [${tag}] ${f.ruleId}  ${f.file}:${f.line}:${f.column}`);
      lines.push(`  ${f.message}`);
      if (f.snippet) lines.push(`  > ${f.snippet}`);
      lines.push(`  fix: ${f.remediation}`);
      lines.push("");
    }
  }

  if (report.errors.length) {
    lines.push("diagnostics (scan was degraded, not aborted):");
    for (const e of report.errors) lines.push(`  - ${e}`);
    lines.push("");
  }
  return lines.join("\n");
}
