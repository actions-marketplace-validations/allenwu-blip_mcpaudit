import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// A correct, narrowly-scoped MCP server. It reads an API key from the
// environment to authenticate to an upstream weather API, but the key is
// NEVER returned to the model — only the forecast text is. No shell, no
// eval, no broad filesystem scope.
const WEATHER_API_KEY = process.env.WEATHER_API_KEY || "";

const server = new McpServer({
  name: "weather-mcp-clean",
  version: "1.0.0",
});

server.tool(
  "get_forecast",
  "Return a short-term weather forecast for a city. Read-only.",
  {
    city: z.string().min(1).max(64),
  },
  async ({ city }) => {
    const res = await fetch(
      "https://api.example-weather.test/v1/forecast?city=" +
        encodeURIComponent(city),
      { headers: { Authorization: `Bearer ${WEATHER_API_KEY}` } },
    );
    const data = await res.json();
    // Only the forecast string is exposed to the model — not the key.
    return {
      content: [{ type: "text", text: String(data.summary || "no data") }],
    };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
