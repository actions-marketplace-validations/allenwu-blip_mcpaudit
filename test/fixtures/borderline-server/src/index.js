import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execFile } from "node:child_process";
import { z } from "zod";

// This server reads a token from the environment for upstream auth, but it
// is used only as a request header constant and is NEVER placed into a tool
// result or description. Static scanners must NOT flag this.
const GIT_TOKEN = process.env.GIT_TOKEN || "";
const authHeader = "token " + GIT_TOKEN; // local use only

const server = new McpServer({ name: "git-mcp-borderline", version: "2.1.0" });

// Safe: execFile with an argv array (no shell, no interpolated command
// string). MCP001 must NOT fire — the command is a string literal and args
// are passed as a separate array.
server.tool(
  "git_status",
  "Show porcelain git status for the configured workspace.",
  { branch: z.string().optional() },
  async ({ branch }) => {
    const args = ["status", "--porcelain"];
    if (branch) args.push("--branch", branch);
    const out = await new Promise((resolve) => {
      execFile("git", args, { cwd: "./workspace" }, (_e, stdout) =>
        resolve(stdout),
      );
    });
    return { content: [{ type: "text", text: String(out) }] };
  },
);

// Safe: a literal command string (no interpolation) — MCP001 must NOT fire.
import { execSync } from "node:child_process";
server.tool("git_version", "Return the git version.", {}, async () => {
  const v = execSync("git --version").toString();
  return { content: [{ type: "text", text: v }] };
});

// Safe: literal eval argument and a numeric parse — MCP005 must NOT fire.
function precomputeConstant() {
  const TWO = eval("1 + 1");
  return Number.parseInt("42", 10) + TWO;
}

// MCP005 guard: `.compile()` / `.eval()` are METHODS on a math-expression
// object (not the global eval / vm builtin). Member-access call → MCP005 must
// NOT fire (provenance discipline, mirroring MCP001/MCP010).
const mathParser = { compile: (s) => ({ eval: (_x) => 0, src: s }) };
function evalFormula(formula, scope) {
  const node = mathParser.compile(formula);
  return node.eval(scope);
}
void evalFormula;

// Safe: comment that mentions process.env and exec but is not code.
// "do not exec(`rm -rf ${dir}`) and never return process.env to the model"
const _docNote = "see README for why we never expose process.env";

server.tool("git_log", "Show recent commits.", {}, async () => {
  const out = await new Promise((resolve) => {
    execFile("git", ["log", "--oneline", "-n", "20"], (_e, s) => resolve(s));
  });
  return {
    content: [
      { type: "text", text: `${precomputeConstant()}\n${String(out)}` },
    ],
  };
});

// ---------------------------------------------------------------------------
// False-positive guards for the deeper rule set (MCP007–MCP014). Every block
// below LOOKS like the corresponding vulnerability but is the safe pattern,
// and must produce ZERO findings.
// ---------------------------------------------------------------------------
import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

// MCP007 guard: a merge with an INLINE OBJECT LITERAL source (developer
// shape, not attacker data) — and an array index assignment (not a proto
// sink). Neither must fire.
function applyDefaults(target) {
  const merged = Object.assign({}, { retries: 3, timeout: 1000 }, target);
  const slots = [];
  for (let i = 0; i < 3; i++) slots[i] = i * 2; // computed numeric index: fine
  return { merged, slots };
}

// MCP008 guard: the ORIGIN is a hardcoded literal; only the path/query
// varies. This is the canonical safe fetch and must NOT fire.
server.tool(
  "weather",
  "Get a forecast for a city (read-only).",
  { city: z.string().min(1).max(64) },
  async ({ city }) => {
    const res = await fetch(
      "https://api.example-weather.test/v1/forecast?city=" +
        encodeURIComponent(city),
    );
    const tmpl = await fetch(`https://api.example-weather.test/v1/by/${city}`);
    void tmpl;
    const data = await res.json();
    return { content: [{ type: "text", text: String(data.summary || "n/a") }] };
  },
);

// MCP009 guard: an obvious placeholder, not a real secret — must NOT fire.
const EXAMPLE_TOKEN = "ghp_your-token-here-XXXXXXXXXXXXXXXXXXXXXXXX";
void EXAMPLE_TOKEN;

// MCP010 guard: path is contained — basename strips any `../`. Must NOT fire.
server.tool(
  "read_doc",
  "Read a markdown doc from the docs folder.",
  { name: z.string() },
  async ({ name }) => {
    const safe = path.basename(name);
    const body = fs.readFileSync(path.join("./docs", safe), "utf8");
    return { content: [{ type: "text", text: body }] };
  },
);

// MCP010 guard (hoisted containment): the path is contained by a
// path.resolve(BASE, path.basename(...)) extracted to a NAMED variable on a
// previous line — idiomatic safe code. The backward-assignment check must
// treat `full` as contained. Must NOT fire.
const DOC_BASE = "./docs";
server.tool(
  "read_doc_hoisted",
  "Read a markdown doc (containment extracted to a variable).",
  { name: z.string() },
  async ({ name }) => {
    const full = path.resolve(DOC_BASE, path.basename(name));
    const body = fs.readFileSync(full, "utf8");
    return { content: [{ type: "text", text: body }] };
  },
);

// MCP011 guard: JSON.parse (data only) and yaml.load with the SAFE schema.
// Neither must fire.
function decode(blob, doc) {
  const a = JSON.parse(blob);
  const b = yaml.load(doc, { schema: yaml.JSON_SCHEMA });
  return { a, b };
}
void decode;
void applyDefaults;

void authHeader;
const transport = new StdioServerTransport();
await server.connect(transport);
