import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureFeedback, loadFeedback } from "../src/feedback.js";

let dir;
let sink;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mcpaudit-fb-"));
  sink = join(dir, "feedback.jsonl");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("captureFeedback / loadFeedback (verbatim contract)", () => {
  it("stores text EXACTLY as written (no trim/normalize)", () => {
    const raw = "  This finding is WRONG.\n\nexecFile is safe, you idiots.  ";
    captureFeedback(sink, { source: "issue-template", text: raw });
    const back = loadFeedback(sink)["issue-template"];
    expect(back).toHaveLength(1);
    expect(back[0].text).toBe(raw); // byte-identical, untransformed
    expect(back[0].product).toBe("mcpaudit");
  });

  it("is append-only and order-preserving", () => {
    captureFeedback(sink, { source: "label", text: "first" });
    captureFeedback(sink, { source: "label", text: "second" });
    const back = loadFeedback(sink).label;
    expect(back.map((r) => r.text)).toEqual(["first", "second"]);
  });

  it("a single corrupt line never drops the rest", () => {
    captureFeedback(sink, { source: "a", text: "good-1" });
    appendFileSync(sink, "{ this is not json\n", "utf8");
    captureFeedback(sink, { source: "a", text: "good-2" });
    const back = loadFeedback(sink).a;
    expect(back.map((r) => r.text)).toEqual(["good-1", "good-2"]);
  });

  it("returns {} for a missing sink", () => {
    expect(loadFeedback(join(dir, "nope.jsonl"))).toEqual({});
  });

  it("groups by source", () => {
    captureFeedback(sink, { source: "x", text: "1" });
    captureFeedback(sink, { source: "y", text: "2" });
    const all = loadFeedback(sink);
    expect(Object.keys(all).sort()).toEqual(["x", "y"]);
  });
});
