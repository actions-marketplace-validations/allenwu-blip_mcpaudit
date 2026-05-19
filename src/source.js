/**
 * source.js — how a scan TARGET becomes a local directory to analyze.
 *
 * The offline path-scan is fully functional today. Fetching a *named*
 * package from a registry is deliberately behind a `PackageSource`
 * interface:
 *   - LocalDirSource    — real, used for `mcpaudit <path>` (no network).
 *   - FakeRegistrySource — TESTS ONLY: maps a name → a local fixture dir, so
 *                          the test suite never touches the network.
 *   - StubRegistrySource — the SHIPPED default for `mcpaudit <package>`. It
 *                          does NOT silently no-op and does NOT do network;
 *                          it throws a clear, actionable error telling the
 *                          user to pass a path (and the operator to wire a
 *                          real registry/tarball fetch later). Honest stub,
 *                          not a fake-passed-as-working.
 */

import { existsSync, statSync } from "node:fs";

/**
 * @typedef {Object} PackageSource
 * @property {(spec:string)=>Promise<string>} materialize resolve `spec` to a
 *   local directory path containing the MCP server's source.
 */

export class LocalDirSource {
  /** @param {string} spec a filesystem path */
  async materialize(spec) {
    if (!existsSync(spec) || !statSync(spec).isDirectory()) {
      throw new Error(`not a directory: ${spec}`);
    }
    return spec;
  }
}

export class FakeRegistrySource {
  /** @param {Record<string,string>} map package name -> local dir */
  constructor(map = {}) {
    this.map = map;
  }
  async materialize(name) {
    const dir = this.map[name];
    if (!dir) throw new Error(`unknown package in FakeRegistrySource: ${name}`);
    return dir;
  }
}

export class StubRegistrySource {
  // eslint-disable-next-line class-methods-use-this
  async materialize(name) {
    throw new Error(
      `registry fetch for "${name}" is not implemented in this build. ` +
        `Pass a local path instead (clone/download the server, then run ` +
        `\`npx mcpaudit ./path-to-server\`). Named-package fetching is an ` +
        `interface the operator wires to a registry/tarball source; the ` +
        `path scan is fully functional and never touches the network.`,
    );
  }
}

/**
 * Decide whether a CLI argument is a filesystem path or a package name.
 * A path that exists, or anything containing a path separator / starting
 * with `.`/`/`/`~`, is treated as a path; otherwise it is a package name.
 * @param {string} arg
 * @returns {{kind:"path"|"package", value:string}}
 */
export function resolveTarget(arg) {
  const looksPathy =
    arg.startsWith(".") ||
    arg.startsWith("/") ||
    arg.startsWith("~") ||
    arg.includes("/") ||
    arg.includes("\\") ||
    (existsSync(arg) && statSync(arg).isDirectory());
  // A scoped package "@scope/name" contains "/" but is NOT a path unless it
  // exists on disk. Disambiguate: starts with "@" and not an existing path.
  if (arg.startsWith("@") && !(existsSync(arg) && statSync(arg).isDirectory())) {
    return { kind: "package", value: arg };
  }
  return looksPathy
    ? { kind: "path", value: arg }
    : { kind: "package", value: arg };
}
