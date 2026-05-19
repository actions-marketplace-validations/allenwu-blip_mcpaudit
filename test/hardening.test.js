/**
 * hardening.test.js — adversarial inputs. A pre-install security scanner is
 * itself run on untrusted code: it must never follow a symlink out of the
 * target, never execute anything, never throw to the host CI, and degrade
 * (not abort) on huge/minified/binary/non-UTF8 files and pathological trees.
 */
import { describe, it, expect } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  symlinkSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeProject } from "../src/analyze.js";

function tmpProject() {
  return mkdtempSync(join(tmpdir(), "mcpaudit-hard-"));
}

describe("symlink safety (never followed, never escapes the target)", () => {
  it("does not follow a symlink pointing OUTSIDE the scan root", () => {
    const root = tmpProject();
    const outside = tmpProject();
    try {
      // a juicy target outside the scanned tree
      writeFileSync(
        join(outside, "secret.js"),
        'import {exec} from "child_process"; exec(`rm -rf ${x}`);',
      );
      writeFileSync(join(root, "index.js"), "const ok = 1;\n");
      // symlink inside root → outside dir
      let linked = true;
      try {
        symlinkSync(outside, join(root, "escape"), "dir");
      } catch {
        linked = false; // some sandboxes block symlink(); skip the assertion
      }
      const r = analyzeProject(root);
      // The outside command-injection MUST NOT appear (we never traversed it)
      expect(r.findings.find((f) => f.ruleId === "MCP001")).toBeUndefined();
      if (linked) {
        expect(r.errors.join("\n")).toMatch(/symlink/i);
      }
      expect(Array.isArray(r.findings)).toBe(true); // never threw
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("does not get stuck on a symlink loop", () => {
    const root = tmpProject();
    try {
      mkdirSync(join(root, "a"));
      writeFileSync(join(root, "a", "x.js"), "const a=1;\n");
      try {
        symlinkSync(join(root, "a"), join(root, "a", "loop"), "dir");
      } catch {
        /* sandbox may block symlink; the test still asserts no-throw */
      }
      const r = analyzeProject(root);
      expect(Array.isArray(r.findings)).toBe(true);
      expect(r).toHaveProperty("errors");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("malformed / pathological file content", () => {
  it("skips a minified/very-long-line bundle (no bogus col-90000 finding)", () => {
    const root = tmpProject();
    try {
      const huge =
        'eval(x);'.repeat(1) +
        ";" +
        "a".repeat(60000) +
        ';eval(userInput);';
      writeFileSync(join(root, "vendor-bundle.js"), huge);
      const r = analyzeProject(root);
      expect(r.errors.join("\n")).toMatch(/minified|long lines|large file/i);
      // it was skipped, so no MCP005 from the giant line
      expect(r.findings).toHaveLength(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("skips a binary file masquerading as .js without throwing", () => {
    const root = tmpProject();
    try {
      writeFileSync(
        join(root, "blob.js"),
        Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x41]),
      );
      const r = analyzeProject(root);
      expect(Array.isArray(r.findings)).toBe(true);
      expect(r.errors.join("\n")).toMatch(/binary|non-text/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("decodes non-UTF8 bytes to U+FFFD instead of crashing", () => {
    const root = tmpProject();
    try {
      // Latin-1 0xE9 ('é') is invalid UTF-8 on its own.
      const buf = Buffer.concat([
        Buffer.from("const s = '"),
        Buffer.from([0xe9, 0xe8]),
        Buffer.from("';\n"),
      ]);
      writeFileSync(join(root, "weird.js"), buf);
      const r = analyzeProject(root);
      expect(Array.isArray(r.findings)).toBe(true); // did not throw
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("emits invalid-JSON manifest as a diagnostic, never a throw", () => {
    const root = tmpProject();
    try {
      writeFileSync(join(root, "mcp.json"), "{ not: valid json, }");
      const r = analyzeProject(root);
      expect(r.errors.join("\n")).toMatch(/invalid JSON/i);
      expect(Array.isArray(r.findings)).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("pathological trees", () => {
  it("bounds a very deep directory tree (no unbounded recursion/crash)", () => {
    const root = tmpProject();
    try {
      let p = root;
      for (let i = 0; i < 60; i++) {
        p = join(p, `d${i}`);
        mkdirSync(p);
      }
      writeFileSync(join(p, "deep.js"), "const x=1;\n");
      const r = analyzeProject(root);
      expect(Array.isArray(r.findings)).toBe(true);
      expect(r.errors.join("\n")).toMatch(/depth/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("never throws and returns the documented shape on a non-directory", () => {
    const root = tmpProject();
    try {
      const file = join(root, "afile.js");
      writeFileSync(file, "const x=1;\n");
      const r = analyzeProject(file); // a FILE, not a dir
      expect(r.errors.length).toBeGreaterThan(0);
      expect(r).toMatchObject({ findings: [], scannedFiles: [] });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
