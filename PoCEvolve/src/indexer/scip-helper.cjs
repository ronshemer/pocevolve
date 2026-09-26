#!/usr/bin/env node
/**
 * scip-helper.cjs — TypeScript indexer bootstrap and invocation.
 *
 * This script bootstraps tsconfig.json for the target testbed, runs
 * @sourcegraph/scip-typescript programmatically (not as an external
 * npx command), then writes the SCIP protobuf output to a temp file.
 *
 * CommonJS is used here because @sourcegraph/scip-typescript itself
 * is a CommonJS module — mixing ESM require() would be unreliable in
 * Node < 23. Using this file as a CommonJS script lets us call the
 * official API directly without spawning processes.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

// ---------------------------------------------------------------------------
// Dependencies (resolved from node_modules of this package)
// ---------------------------------------------------------------------------

const { indexCommand } = require('@sourcegraph/scip-typescript');

// ---------------------------------------------------------------------------
// Constants & defaults
// ---------------------------------------------------------------------------

const STUB_INDEX_NAME = 'scip-helper-stub.ts';
const DEFAULT_TSCONFIG_NAME = 'tsconfig.json';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Ensure a directory exists (recursive). */
function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

/** Write text to a file (create or overwrite). */
function writeFile(filePath, content) {
  fs.writeFileSync(filePath, content, 'utf8');
}

/** Read JSON from a file. Returns null on failure. */
function readJSON(pathToRead) {
  try {
    return JSON.parse(fs.readFileSync(pathToRead, 'utf8'));
  } catch {
    return null;
  }
}

/** Bootstrap a tsconfig.json for the given directory if one doesn't exist. */
function bootstrapConfig(testbedDir) {
  const tsconfigPath = path.join(testbedDir, DEFAULT_TSCONFIG_NAME);

  // If tsconfig already exists, nothing to do.
  if (fs.existsSync(tsconfigPath)) {
    return;
  }

  console.error(
    `[scip-helper] No ${DEFAULT_TSCONFIG_NAME} found in ${testbedDir}. Generating a minimal one.`,
  );

  const tsconfig = {
    compilerOptions: {
      // Use 'NodeNext' to properly resolve modern ES module syntax.
      module: 'NodeNext',
      // Target modern JavaScript for compatibility.
      target: 'ES2022',
    },
    include: ['**/*.ts'],
  };

  writeFile(tsconfigPath, JSON.stringify(tsconfig, null, 2));
}

/** Create a small stub file so scip-typescript has something to index. */
function bootstrapStub(testbedDir) {
  const indexPath = path.join(testbedDir, STUB_INDEX_NAME);

  console.error(`[scip-helper] Generating stub index at ${indexPath}.`);
  writeFile(
    indexPath,
    '// Auto-generated scip-typescript stub file.\n// This exists so the TypeScript compiler has a valid entry point. ' +
      '\ntype Foo = string | number;\nconst bar: Foo = "hello";\nexport { Foo, bar };\n',
  );
}

/** Clean up any temp directory created by this helper. */
function cleanupTempDir(dirPath) {
  if (dirPath && fs.existsSync(dirPath)) {
    try {
      fs.rmSync(dirPath, { recursive: true });
    } catch {
      // Ignore errors during cleanup.
    }
  }
}

/** Clean up the temporary tsconfig and stub files in the testbed. */
function teardown(testbedDir) {
  const tsconfigPath = path.join(testbedDir, DEFAULT_TSCONFIG_NAME);
  const indexPath = path.join(testbedDir, STUB_INDEX_NAME);

  // Remove bootstrap artefacts if they were created.
  ['tsconfig', 'index'].forEach((name) => {
    if (path.join(testbedDir, `${name}${name === 'tsconfig' ? '.json' : '.ts'}`).startsWith(testbedDir)) {
      try {
        fs.rmSync(path.join(testbedDir, name === 'tsconfig' ? DEFAULT_TSCONFIG_NAME : STUB_INDEX_NAME), { force: true });
      } catch {
        // Ignore errors during teardown.
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Main: argument parsing & execution
// ---------------------------------------------------------------------------

function main() {
  // Minimal CLI arg parser (mirrors the old ESM helper).
  const args = process.argv.slice(2);
  let testbedDir = null;
  let outputPath = null;

  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--cwd' && args[i + 1]) {
      testbedDir = path.resolve(args[i + 1]);
      i += 1;
    } else if (args[i] === '--output' && args[i + 1]) {
      outputPath = path.resolve(args[i + 1]);
      i += 1;
    }
  }

  if (!testbedDir || !fs.existsSync(testbedDir)) {
    process.stderr.write('[scip-helper] Error: --cwd must point to an existing directory.\n');
    process.exit(1);
  }

  // Create temp output file.
  const tmpOutput = outputPath || path.join(os.tmpdir(), `scip-output-${Date.now()}.scip`);

  try {
    // Bootstrap: create tsconfig + stub index if missing.
    bootstrapConfig(testbedDir);
    bootstrapStub(testbedDir);

    console.error(`[scip-helper] Indexing ${testbedDir} → ${tmpOutput}`);

    // -----------------------------------------------------------------------
    // Run @sourcegraph/scip-typescript programmatically (not via npx).
    // -----------------------------------------------------------------------
    indexCommand([testbedDir], {
      cwd: testbedDir,
      output: tmpOutput,
      skipInstallCheck: true,
    });

    console.error(`[scip-helper] Index complete. Output: ${tmpOutput}`);
  } catch (err) {
    // Log the error to stderr but don't exit — the Python caller handles this.
    if (typeof err.message === 'string' && err.message.includes('ENOENT')) {
      process.stderr.write(
        '[scip-helper] Error: TypeScript or node-gyp not found on PATH. Please install Node.js and try again.\n',
      );
    } else {
      process.stderr.write(`[scip-helper] Error during indexing: ${err.message}\n`);
    }
    throw err;
  } finally {
    // Always clean up bootstrap artefacts.
    teardown(testbedDir);
  }

  // Write output path to stdout so Python caller can read it.
  process.stdout.write(tmpOutput + '\n');
}

main();
