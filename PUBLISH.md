# PUBLISH — mcp-audit-cli (Allen-only owner gates)

Built & independently reviewed: real Node 20 static scanner, 66 tests green from clean install (network+keys hard-blocked), 14 real detection rules with provenance checks (so it stays quiet on safe-looking code instead of crying wolf), fails open (never breaks the host project's CI), honest README (the 118 figure is attributed to an external audit, no invented benchmarks), no LLM. **AI never does the steps below — publish/identity/money, only you.**

## Gate 1 — Publish (free CLI drives adoption; $0 cost)
1. Create a **public GitHub repo** under your account/org (e.g. `<owner>/mcpaudit`).
2. `products/mcp-audit-cli/package.json`: set `"private": false` (required before any `npm publish`; the `npx <owner>/...` + Action path works regardless, but registry publish refuses while private).
3. Replace `<OWNER>` placeholders in `README.md`/`examples/` with your real GitHub owner handle.
4. Push `products/mcp-audit-cli/` to the repo root; tag a release (`v0` + SHA-pinned); optionally `npm publish` for true `npx mcpaudit`; enable Marketplace for the Action.
5. Create label **`mcpaudit-feedback`** in that repo (the primary channel where real user reports come in, stored word-for-word, for this bet).
6. Show HN / dev-channel post = the faceless way the work gets out (AI drafts; you post — any public technical claim is source-verified first).

→ Real usage signal then flows to the kill line (the threshold below which this bet gets dropped): `<1 paid monitoring conversion AND <300 npx invocations / <50 stars within the first review cycle` → else default-KILL at your next review.

## Gate 2 — payment account (the revenue gate; shared across the whole operation)
Free CLI = $0 by design. A paid CI/continuous-monitoring tier later needs a **merchant-of-record account in your name** (MoR — a service like Paddle / Lemon Squeezy / Polar that sells on your behalf and handles tax). No payment code exists here. **Same single gate as every other bet: until this account exists, the entire operation collects $0 and no money-making kill-threshold can be scored.** This — not how many products get built — is the binding constraint on getting to revenue fast.

## Budget (spec §8 / DR-3)
Free CLI/Action = no hosting cost. Paid tier / any deploy = real spend; single >¥500 or per-bet cumulative >¥2k must be ratified by you before spend.
