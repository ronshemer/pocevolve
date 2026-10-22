# PoCEvolve Architecture

PoCEvolve is an iterative exploit generation system for CVE proof-of-concept code. The current branch includes a standalone, AST-assisted analysis utility that maps deleted lines in CVE fix diffs to enclosing functions and reports likely package entry points. It does not currently build a SCIP call graph or trace tainted values through calls.

## Main pipeline (`src/`)

```text
config.py → generator.py | evolver_llm.py | evolver_pocgen.py
                      ↓
                  pipeline.py
                      ↓
       evaluator.py → evolve_prompt.py → llm.py / prompts.py
```

The generation pipeline is independent of the static-analysis CLI. The analysis tool can be run on its own against a vulnerable checkout and a VFC patch.

## Static analysis (`src/graph_analysis/`)

### Flow

1. Load a fix diff from the VFC data or accept a patch file.
2. Parse deleted lines into `DiffEntry` records.
3. Resolve the enclosing JavaScript function for each deleted line using espree when available, with source-pattern fallbacks.
4. Identify package entry-point files from `package.json` metadata and CommonJS exports.
5. Return structured JSON with matched diff entries, entry-point files, and target-method summaries.

Results currently use `mode="entry_points_only"`. The `taint_flows` field remains empty because call-graph indexing and taint propagation are not part of the current implementation.

### Modules

| Module | Role |
|---|---|
| `__init__.py` | Public `analyze_cve()` and `analyze_testbed()` helpers |
| `__main__.py` | CLI for supplied or automatically resolved testbeds and diffs |
| `analyzer.py` | Diff parsing, enclosing-function lookup, and result assembly |
| `diff_parser.py` | Parses unified diffs, including deleted-line locations |
| `method_resolution.py` | Resolves enclosing functions using espree and source-pattern fallbacks |
| `testbed_manager.py` | Creates or reuses a checkout at the parent of a VFC fix commit |
| `vfc_loader.py` | Loads VFC records and their fix diffs |
| `_types.py` | Analysis result data classes |

### Run commands

From the repository root:

```bash
# Create/reuse the vulnerable checkout and write static-analysis JSON
bash PoCEvolve/eval/analyze_cve.sh SNYK-JS-HOTFORMULAPARSER-541328

# Analyze a supplied checkout and patch
cd PoCEvolve
python3 -B -m src.graph_analysis --testbed /path/to/package --diff /path/to/fix.diff --json
```

`eval/prepare_cve.sh` is an alias for the first command. Checkouts are cached under `src/git_testbeds/auto/`.

## Datasets and resources

- `datasets/` — CVE dataset files
- `SecBench.js/` — benchmark data and local package repositories
- `resources/validate_functions/` — validation function definitions

## Docker

```bash
docker compose -f docker-compose.yml up -d
docker exec -it exploit-generation bash
```

Prefer the host for Ollama localhost access; a container may not be able to reach the host's Ollama instance.
