/** Thin Node.js wrapper around @sourcegraph/scip-typescript.
 *
 * scip-typescript refuses to index pure-JavaScript projects unless it sees
 * at least one TypeScript file plus a valid tsconfig.json.  This helper sets
 * up the minimal bootstrap artifacts (tsconfig + empty stub), runs the
 * indexer, then cleans up — so Python callers don't have to manage temp files.
 *
 * Usage:
 *   node scip-helper.mjs --cwd /path/to/package --output /path/to/index.scip [--verbose]
 */

import { execFile } from "node:child_process";
import { gzipSync } from "node:zlib";
import { promises as fs } from "node:fs";
import { parseArgs, promisify } from "node:util";
import { tmpdir } from "node:os";
import { join, basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

/* ------------------------------------------------------------------ */
/* CLI arg parsing                                                     */
/* ------------------------------------------------------------------ */

const { values, argv } = parseArgs({
  options: {
    cwd:   { type: "string" },
    output:{ type: "string" },
    verbose:{ type: "boolean", default: false },
  },
  allowPositionals: true,
});

if (!values.cwd || !values.output) {
  console.error("Usage: scip-helper.mjs --cwd <pkg-root> --output <scip-path> [--verbose]");
  process.exit(1);
}

/* ------------------------------------------------------------------ */
/* Bootstrap helpers                                                   */
/* ------------------------------------------------------------------ */

const TS_CONFIG = JSON.stringify({
  compilerOptions: {
    target: "ES2020",
    module: "commonjs",
    strict: true,
    esModuleInterop: true,
    skipLibCheck: true,
    forceConsistentCasingInFileNames: true,
    allowJs: true,
  },
  include: ["**/*.ts", "**/*.js"],
  exclude: ["node_modules", "dist"],
}, null, 2);

const STUB_TS = "// Empty stub — scip-typescript requires ≥1 .ts file per project.\nexport {};\n";

async function bootstrap(pkgRoot) {
  const tsPath = join(pkgRoot, "tsconfig.json");
  const stubPath = join(pkgRoot, "__scip_bootstrap_stub__.ts");

  // Only write if absent — preserve user's own config / don't clobber existing tsconfig.
  if (!await fs.stat(tsPath).catch(() => false)) {
    await fs.writeFile(tsPath, TS_CONFIG, "utf-8");
  }

  const files = await fs.readdir(pkgRoot);
  const hasTs = files.some(f => f.endsWith(".ts") || f.endsWith(".tsx"));
  if (!hasTs) {
    await fs.writeFile(stubPath, STUB_TS, "utf-8");
  }

  return { tsPath, stubPath };
}

async function teardown(pkgRoot, { tsPath, stubPath }) {
  try { await fs.rm(tsPath, { force: true }); } catch {}
  // Only remove our synthetic stub — never delete user files.
  if (stubPath.includes("__scip_bootstrap_stub__")) {
    try { await fs.rm(stubPath, { force: true }); } catch {}
  }
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

async function main() {
  const pkgRoot = values.cwd;
  const output  = values.output;

  // Bootstrap tsconfig + stub if missing
  const paths = await bootstrap(pkgRoot).catch(err => {
    console.error(`Bootstrap failed: ${err.message}`);
    process.exit(2);
  });

  let exitCode = 0;
  try {
    const cmd   = ["npx", "--yes", "@sourcegraph/scip-typescript", "index", "--output", output];
    const execFileAsync = promisify(execFile);

    try {
      const { stdout, stderr } = await execFileAsync(cmd[0], cmd.slice(1), {
        cwd: pkgRoot,
        env: { ...process.env },
        timeout: 300_000,   // 5 min — same as Python default
        stdio: values.verbose ? "inherit" : ["pipe", "pipe", "pipe"],
      });

      // scip-typescript 0.4+ writes raw uncompressed protobuf — gzip it for compatibility.
      const buf = await fs.readFile(values.output);
      await fs.writeFile(values.output, gzipSync(buf));
      if (stderr) console.error(stderr.trim());
      exitCode = 0;
    } catch (err) {
      // promisify(execFile) rejects on non-zero exit, signal, or timeout.
      exitCode = err.killed || err.signal === "SIGTERM" ? 124 : (parseInt(err.code, 10) || 1);
      console.error(`scip-typescript failed (rc=${exitCode}): ${err.message}`);
    }

  } finally {
    // Always clean up, even on exit/kill
    await teardown(pkgRoot, paths).catch(() => {});
  }

  process.exit(exitCode);
}

main().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(3);
});
