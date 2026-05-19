import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { exec } from "node:child_process";
import vm from "node:vm";
import fs from "node:fs";
import _ from "lodash";
import yaml from "js-yaml";
import { unserialize } from "node-serialize";
import { z } from "zod";

const server = new McpServer({ name: "devtools-mcp-vulnerable", version: "0.0.1" });

// MCP001: command injection — exec() with an interpolated tool argument.
server.tool(
  "ping_host",
  "Ping a host and return latency.",
  { host: z.string() },
  async ({ host }) => {
    const cmd = `ping -c 1 ${host}`;
    const out = await new Promise((resolve) => {
      exec(cmd, (_e, stdout) => resolve(stdout));
    });
    return { content: [{ type: "text", text: String(out) }] };
  },
);

// MCP002: environment / credential exfiltration into an LLM-visible result.
server.tool("debug_env", "Dump runtime configuration.", {}, async () => {
  return {
    content: [{ type: "text", text: JSON.stringify(process.env) }],
  };
});

// MCP005: dangerous dynamic eval reachable from tool input.
server.tool(
  "calc",
  "Evaluate an arithmetic expression.",
  { expr: z.string() },
  async ({ expr }) => {
    const result = eval(expr);
    vm.runInThisContext(expr);
    return { content: [{ type: "text", text: String(result) }] };
  },
);

// MCP007: prototype pollution — recursive merge of attacker-shaped input.
server.tool(
  "set_config",
  "Deep-merge user settings.",
  { patch: z.object({}) },
  async ({ patch }) => {
    const config = {};
    _.merge(config, patch); // attacker `__proto__` walks into Object.prototype
    return { content: [{ type: "text", text: "ok" }] };
  },
);

// MCP008: SSRF — fetch() pointed at a fully attacker-controlled URL.
server.tool(
  "fetch_url",
  "Fetch a URL and return the body.",
  { target: z.string() },
  async ({ target }) => {
    const res = await fetch(target);
    return { content: [{ type: "text", text: await res.text() }] };
  },
);

// MCP009: a real-looking credential hardcoded in a tool description/source.
const LEAKED = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab";
server.tool(
  "deploy",
  `Deploy using token ${LEAKED}`,
  {},
  async () => ({ content: [{ type: "text", text: "deployed" }] }),
);

// MCP010: path traversal — fs.readFile on an unsanitised tool-supplied path.
server.tool(
  "read_file",
  "Read a file from the workspace.",
  { name: z.string() },
  async ({ name }) => {
    const body = fs.readFileSync("./data/" + name, "utf8");
    return { content: [{ type: "text", text: body }] };
  },
);

// MCP011: unsafe deserialization of attacker data (RCE) + unsafe yaml.load.
server.tool(
  "load_state",
  "Restore a serialized state blob.",
  { blob: z.string(), doc: z.string() },
  async ({ blob, doc }) => {
    const state = unserialize(blob);
    const parsed = yaml.load(doc);
    return { content: [{ type: "text", text: JSON.stringify({ state, parsed }) }] };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
