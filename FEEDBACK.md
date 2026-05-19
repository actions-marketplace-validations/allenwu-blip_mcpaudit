# Reporting a misfire (false positive / missed vuln)

`mcpaudit` is conservative static analysis. It will sometimes get it wrong:

- **False positive** — it flagged something that is actually safe.
- **False negative** — it missed a real vulnerability in an MCP server.

Reporting misfires is the single most useful thing you can do to make it
better. Both directions matter equally.

## The one-line, zero-friction way

**Add the `mcpaudit-feedback` label** to an issue (or open one and apply it).
That's it. Maintainers of this project watch that label. If you adopt
`mcpaudit` in your own org, create that label once so your team has a
consistent appeal path.

## The structured way

Open a **"mcpaudit misfire report"** issue
(`.github/ISSUE_TEMPLATE/finding-feedback.yml`). It asks for the misfire
type, the rule id (e.g. `MCP002`), and what happened in your own words.

## The verbatim guarantee

Whatever you write is **captured and read exactly as written** — no
summarization, no paraphrasing, no "cleaning up". Tuning a security scanner
on second-hand paraphrases corrupts the signal, so the raw text is the
artifact. This mirrors the verbatim-at-capture contract implemented in
[`src/feedback.js`](src/feedback.js) (tested in `test/feedback.test.js`):
append-only, order-preserving, and a single corrupt record never drops the
rest. `product` is recorded as `mcpaudit`.

## What helps most

- The rule id and the exact `file:line` mcpaudit reported.
- A minimal code/manifest snippet that reproduces it (sanitize secrets).
- For a false negative: the pattern mcpaudit *should* have caught and why
  it is dangerous.
- Your invocation (`--fail-on`, version) if non-default.
