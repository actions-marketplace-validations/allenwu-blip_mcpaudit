# LAUNCH — mcp-audit-cli (mcpaudit)

**DRAFT — operator reviews and posts. Public technical claims are yours to send.**
All claims below are drawn from the reviewed README only. The 118-findings figure
is from the cited external audit — attribute it correctly or omit it. Do not add
benchmarks, accuracy numbers, or detection-rate claims not already in the README.

---

## Show HN title

```
Show HN: mcpaudit – static security scanner for MCP servers, zero install, no network
```

## Show HN body

```
An MCP server (Model Context Protocol — the standard way to give an AI agent
new tools) is code you download and let the agent run. Before you trust one,
you should be able to run a quick security check on it. There isn't really a
dedicated tool for that yet — mcpaudit is an attempt at it.

npx <owner>/mcpaudit ./path-to-an-mcp-server

No install, no config, no API key, no network. It reads the server's JS/TS
source and its settings file, runs 14 fixed detection rules, and reports
findings with a severity, the exact file:line:col location, a plain
explanation of why the rule fired, and a concrete fix. It never runs the code
it checks.

The rules cover things like: command injection (a shell command built from
non-fixed input), credentials or environment variables leaking into output the
AI can read, an over-broad file access scope in the settings file,
unrestricted "any tool" wildcards, dangerous dynamic code execution, hardcoded
secrets, and pulling-and-running unpinned remote code (curl|sh, npx@latest,
etc.). Each rule is tuned to avoid obvious false alarms — a fixed
exec("constant string") does not fire.

Fails open on purpose: if mcpaudit itself breaks, it prints an error and exits
0. A security checker that is itself broken must not block every build.

An independent 2026 audit found 118 security findings across 68 MCP packages —
full citation in the README. mcpaudit is a tool for running that kind of check
yourself, offline, before you trust a package. It does not claim to reproduce
those findings; the rules are tuned around the most common pattern types.

66 tests green from a clean install (network and keys hard-blocked in CI). MIT.

GitHub: [link]
```

---

## One-paragraph repo description

```
mcpaudit is a static pre-install security scanner for MCP (Model Context Protocol)
servers. Run `npx mcpaudit <path>` to check a server's JS/TS source and manifest
for command injection, credential/env exfiltration into LLM-visible output,
over-broad filesystem scope, unrestricted tool wildcards, dynamic eval, and unpinned
remote execution — before wiring it into an AI agent. No install, no config, no
network, no API key. Works as a CLI and as a GitHub Action. Fail-open: internal
errors never break your pipeline. MIT license.
```

---

## What it is / honest limitations blurb
(For a pinned issue, Marketplace description, or README TL;DR)

```
mcpaudit is pattern-based static analysis — not a sandbox and not taint analysis.
It will miss things (obfuscated code, deep indirection, runtime-only behaviour,
malicious transitive dependencies) and will sometimes flag false positives on
unusual but safe patterns. No precision/recall or detection-rate figures are
claimed — there is no published labeled corpus behind the rules. The 118-findings
figure in the README is from an external 2026 audit, not produced by this tool.
Use mcpaudit as one layer alongside dependency scanning, least-privilege
configuration, and human review.
```

---

## Notes for operator before posting

- Replace `<owner>` and `[link]` placeholders with real values once the repo
  is public.
- The 118-findings / 68-packages figure is attributed to the external dev.to
  audit cited in the README. Use it only with that attribution; do not present
  it as a claim about this tool's detection capability.
- The Show HN body uses "I" once — if you prefer fully faceless/product-voice,
  replace "I" phrases with product-voice ("mcpaudit is...").
- Do not add precision/recall numbers, detection rates, or percentage-of-packages-
  covered claims — the README explicitly disclaims these and adding them here
  would be an unsubstantiated assertion.
- If you publish to npm before posting, substitute the real `npx` invocation
  (e.g. `npx mcpaudit ./path`) in the Show HN body.
- A terminal screenshot of a real scan output against the vulnerable fixture in
  `test/fixtures/` is the most useful visual to add before posting.
