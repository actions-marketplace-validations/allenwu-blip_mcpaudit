# mcp-audit-cli (`mcpaudit`) — spec

> This started as a 6-rule MVP and has been deepened to a 14-rule scanner
> with SARIF output, a dependency/manifest-aware layer, an offline
> baseline-diff continuous-monitoring mechanic, and adversarial-input
> hardening. The MVP section below is kept and extended in place; see
> "Depth (post-MVP)" for what was added and the honest scope of each.

A fast **static** pre-install security scanner for MCP (Model Context
Protocol) servers. `npx mcpaudit <path>` before you wire a server into your
agent.

## Problem (evidence-grounded, see README for citations)
An independent 2026 audit found **118 security findings (5 critical, 9 high)
across 68 of 194 surveyed MCP packages** — shell/command injection,
environment-variable & credential leakage into LLM-visible context, and
over-broad filesystem/tool scope — and **9 of 11 major MCP directories publish
packages with zero automated security review**. Developers want a CVE-like
check *before* an MCP server runs inside an autonomous agent. (Figures are
attributed to the cited external audit, not measured by this tool.)

## What it does (MVP)
Given a local directory (an MCP server's source tree, possibly the unpacked
contents of an npm package), `mcpaudit`:
1. Walks the source files (`.js .mjs .cjs .ts .tsx`) plus the package
   manifest (`package.json`) and any MCP manifest (`mcp.json` /
   `server.json` / `*.mcp.json`).
2. Runs a set of **pure, deterministic rules** producing findings. No code in
   the scanned project is executed. Each finding has:
   `{ id, severity, file, line, column, message, remediation, ruleId,
   snippet }`.
3. Prints a **human report** (default) or **`--json`** (machine / CI).
4. Exits non-zero iff a finding's severity ≥ a configurable gate
   (`--fail-on`, default `high`) so it is usable as a CI gate. Any *internal*
   error is caught, reported as a diagnostic, and the process still exits `0`
   (it must never break the host CI like a crashing linter).

## Rules (MVP — each documents *why* it fires; conservative)
| id | severity | detects |
|----|----------|---------|
| `MCP001` command-injection | critical | `child_process` `exec`/`execSync`/`spawn`/`spawnSync`/`execFile` whose command string is built from a **non-literal** (template literal with `${}`, string `+` concat, or a bare variable) — classic shell/command injection sink. `exec` with a single string literal does **not** fire. |
| `MCP002` env-exfiltration | high | `process.env` (whole object or a specific var) flowing into an MCP **tool result** (`content[].text` / a returned string) or into a tool/`server` **description** / `inputSchema` — i.e. credentials become LLM-visible. Heuristic, source-pattern based; explained per finding. |
| `MCP003` broad-fs-scope | high | An MCP manifest or filesystem-server config granting a **root / home / `/` / drive-root** directory, or a `..`-escaping or `*`-glob path as an allowed root. |
| `MCP004` unrestricted-tool-glob | medium | A tool/permission allowlist declared as `"*"` / `["*"]` / `allowAllTools: true` / regex `.*` — unscoped tool exposure. |
| `MCP005` dangerous-eval | high | `eval(<non-literal>)`, `new Function(<non-literal>)`, or `vm.runInThisContext`/`runInNewContext` with non-literal code — dynamic code execution reachable from tool input. |
| `MCP006` unpinned-remote-exec | medium | `npx`/`uvx`/`pip install`+run/`curl … | sh` patterns inside source or manifest `command`/`args` that fetch & execute remote code unpinned. |

Conservative-by-design (avoid newbie false positives): literal-only
`exec("ls")`, `eval("1+1")`, env var merely read into a config constant and
**not** returned to the model, and a scoped relative allowed dir do **not**
fire. False-positive avoidance is asserted by the `borderline` fixture test.

## Depth (post-MVP) — added rules, outputs, layers (each honest)

**Additional rules (pure, provenance-gated, conservative — borderline stays 0):**
| id | severity | detects | does NOT fire on |
|----|----------|---------|------------------|
| `MCP007` proto-pollution | high | recursive/deep merge or deep-set (`_.merge`/`defaultsDeep`/`setWith`/`deepmerge`/…) from a non-literal source; computed `obj[k]=v` where `k` can be `__proto__`/`constructor` | inline-object-literal merge source; numeric array index |
| `MCP008` ssrf-fetch | high | `fetch`/`axios`/`got`/`https.request` where the URL **origin** is attacker-influenceable (bare var, `${host}` in authority, leading-variable concat) | fixed origin + only path/query varying; fully literal URL; `new URL(p, FIXED_BASE)` |
| `MCP009` hardcoded-secret | critical | string literal matching AWS/GitHub/Slack/Google/OpenAI-style/Anthropic key, PEM private key, or JWT | placeholders (`your-`,`XXXX`,`<…>`,`example`); comment-only mentions |
| `MCP010` path-traversal | high | `fs.*` path that is a bare var or concat/template with no `path.join`/`resolve`/`normalize`/`basename` containment (requires an `fs` binding) | `path.basename`/`path.join`-contained paths; literal paths; bare `readFile(` with no `fs` import |
| `MCP011` unsafe-deserialize | critical / high | `node-serialize`/`serialize-javascript` `unserialize`/`deserialize` of non-literal (critical); `js-yaml` `load()` default schema (high) | `JSON.parse`; `yaml.load(x,{schema:JSON_SCHEMA})`; literal payload |
| `MCP012` dangerous-lifecycle | critical | `preinstall`/`install`/`postinstall`/`prepare` script piping a network download / base64-decode into a shell, or an obfuscated one-liner | normal build hooks (`tsc`, `node build.js`, `husky install`); curl in a non-lifecycle script |
| `MCP013` manifest-secret | critical | a credential pattern (as MCP009) inside `package.json`/`mcp.json` (e.g. `env` block) | placeholders; `${VAR}` references |
| `MCP014` risky-dependency | medium / low | `git+`/url/tarball dependency source (medium); name 1 edit from a popular package (**low advisory only**) | exact registry version of a known-good dep; an old version (no CVE claim made) |

Manifest rules are **shape-aware** (a `package.json`-only rule never fires on
`mcp.json` and vice-versa). Finding ids hash `rule|file|line|col|message` so
two distinct findings at one location stay distinct yet deterministic.

**Output formats:** `--json` (now optionally carries a `baseline` block),
`--sarif` (SARIF v2.1.0 for `github/codeql-action/upload-sarif`; result
`partialFingerprints.mcpauditFindingId` = the stable id for GitHub de-dup),
and `--monitor-json` (the structured monitoring record). All pure +
deterministic + schema-tested.

**Dependency/manifest-aware layer:** `MCP012`/`MCP013`/`MCP014` parse the
package manifest for install-time-dangerous lifecycle scripts, committed
secrets, and risky declared dependency *sources/shapes*. **Fully static and
offline — no registry contact, no bundled vuln DB, no CVE/malware
assertion.** Registry fetch of a *named* package stays the existing
interface+stub.

**Continuous-monitoring SURFACE (free OSS scaffold only):**
`src/baseline.js` is pure: `buildBaseline(report)` writes a deterministic,
timestamp/host-free baseline; `diffAgainstBaseline` reports NEW/FIXED;
`monitoringRecord` emits the machine contract a hosted tier would consume.
CLI `--baseline-write` / `--baseline` (gate **only on NEW** regressions) /
`--monitor-json`. A clearly-marked `// PAID TIER (operator wires later)`
seam documents where a hosted/alerting/fleet offering would attach. **No
network, no upload, no scheduler, no accounts, no billing, no
merchant-of-record exists anywhere in this codebase — by design.**

**Hardening (the scanner is itself run on untrusted code):** the tree walk
**never follows symlinks** (cannot be steered to `/etc` or into a loop) and
asserts every descended dir stays within the canonicalised root; huge,
minified/very-long-line, binary, and non-UTF8 files are **skipped with a
diagnostic** (never mis-located findings, never a DoS); directory depth is
bounded; the scanned project is **never executed**; `analyzeProject` never
throws and the diagnostics array is capped. Asserted by `hardening.test.js`.

## Public library API (pure, testable; zero network)
- `analyzeProject(rootDir, opts) -> { findings, scannedFiles, errors }` —
  reads the tree, dispatches rules. Deterministic, no network.
- `analyzeSource(code, relPath) -> Finding[]` — per-file rules.
- `analyzeManifest(json, relPath) -> Finding[]` — manifest rules.
- `SEVERITY_ORDER`, `gate(findings, failOn) -> boolean` — CI gate math.
- `formatHuman(report, opts) -> string`, `formatJson(report) -> string`,
  `formatSarif(report, version) -> string` (SARIF v2.1.0, deterministic).
- `buildBaseline(report)`, `diffAgainstBaseline(report, baseline)`,
  `monitoringRecord(report, diff)` — pure baseline/monitoring (no I/O here;
  the CLI reads/writes). Documented `// PAID TIER` seam, no money/network.
- `PackageSource` interface + `LocalDirSource` (real) +
  `FakeRegistrySource` (tests) — fetching a *named* package is behind an
  interface; **tests scan a local fixture dir only, never the network.**

## CLI (`bin/mcpaudit.js`, Node ≥ 20, zero runtime deps)
`npx mcpaudit <path|package> [--json] [--sarif]
[--fail-on critical|high|medium|low|none] [--baseline <f>]
[--baseline-write <f>] [--monitor-json] [--quiet]`. A bare *package name*
uses `PackageSource`; the default real source is a documented stub that
explains it needs the operator to wire a registry/tarball fetch (it does NOT
silently no-op and does NOT do network in tests). A filesystem path works
fully offline today. With `--baseline`, the gate fires **only on NEW
findings** (regressions) so triaged findings don't re-break the build.

## GitHub Action (`action.yml`, thin Node20 wrapper)
Inputs: `path` (default `.`), `fail-on`, `json`, `sarif`, `sarif-file`,
`baseline`. Outputs: `total`/`critical`/`high`/`medium`/`low`/`gate`, plus
`new`/`fixed` (with a baseline) and `sarif-file` (with `sarif:true`). Calls
the same pure scan; surfaces the report + a GitHub annotation per finding;
optionally writes a SARIF file for `github/codeql-action/upload-sarif`; the
step's exit code is the gate (NEW-only with a baseline). Internal errors
never fail the workflow (exit 0 + annotation).

## Feedback hook (verbatim — mirrors the operation pattern)
- Documented `mcpaudit-feedback` issue label.
- `.github/ISSUE_TEMPLATE/finding-feedback.yml` (false positive / missed
  vuln).
- `FEEDBACK.md` documenting the one-line low-friction report + the
  verbatim-capture guarantee.
- `src/feedback.js` — append-only, order-preserving, one corrupt line never
  drops the rest. Captured **exactly as written**, no transformation.

## LLM usage
None. This is static analysis; pure rules only. (If a future heuristic ever
needs an LLM it must be an injected interface with a Fake for CI; real adapter
Anthropic Claude via `ANTHROPIC_API_KEY` only, never OpenAI, never hardcoded,
never exercised in CI.)

## Test plan (TDD, no network, no key)
Fixtures under `test/fixtures/`:
- `clean-server/` — a correct MCP server → **zero findings**.
- `vulnerable-server/` — **every rule MCP001–MCP014** fires with the
  **correct severity and file:line**.
- `borderline-server/` — legit patterns that *look* scary across all 14
  rules (literal `exec`/`eval`, env read into a non-returned config, scoped
  relative dir, fixed-origin `fetch`, `path.join`/`basename`-contained file
  access, safe-schema `yaml.load`, placeholder secret, normal build hooks,
  exact-pinned known-good deps) → **zero findings** (false-positive guard).
`npm test` (vitest) covers: every rule's positive + negative case, gate
math, all formatters incl. SARIF schema correctness, the baseline-diff
mechanic (pure + CLI round-trip), the `FakeRegistrySource`, adversarial
hardening (symlink escape/loop, minified/binary/non-UTF8, deep trees,
never-throws), and end-to-end `analyzeProject` on all fixtures. No test
performs network I/O or needs an API key; baseline tests use OS tmp dirs.

## Non-goals (stated honestly in README "Limitations")
- Not a sandbox / not dynamic taint analysis — pattern-based static rules
  miss obfuscated, indirected, or runtime-only vulns and will have some false
  negatives and occasional false positives. Notably MCP010 deliberately
  under-reports `path.join`-contained paths (accepted FN, documented).
- No published accuracy/benchmark numbers (no labeled corpus); the external
  118-findings figure is **cited, not claimed as ours**.
- The dependency layer makes **no CVE/malware claim** and contacts no
  registry; pair with a real SCA tool.
- No hosted/continuous-monitoring tier or billing here. The OSS CLI ships
  only the offline baseline-diff mechanic + the machine record a hosted tier
  would consume; a clearly-marked `// PAID TIER` seam shows where an operator
  would attach one. **No payment / merchant-of-record / account / network /
  upload code exists in this repo.**
- Named-package fetching from a registry is an interface stub for the
  operator to complete; the offline path-scan is fully functional.
