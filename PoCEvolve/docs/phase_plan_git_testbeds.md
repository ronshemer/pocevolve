# Phase Plan: Git-Repo Testbeds for Dataflow Analysis

## Problem Statement

Current graph analysis fails for git-cloned testbeds because:
1. `_detect_node_modules_pkg()` returns `None` when no `node_modules/` directory exists (git repos have bare source files)
2. Without a package prefix, js_call_graph edges use bare filenames (`index.js`) as keys
3. Matched methods have full symbols (`index.js::fn_Arpping`) that don't match these bare keys
4. Graph filtering returns 0 nodes because `node_modules/arpping` doesn't exist in git repos
5. BFS traversal can't find edges because adjacency list keys are bare filenames, not file-path-prefixed symbols

## Goal

Implement a new git-repo-based testbed mechanism alongside existing node_modules testbeds that:
- Clones the vulnerable package's own git repo at the right commit (last version before fix)
- Produces a properly-scoped index for graph analysis
- Enables accurate dataflow taint propagation tracing

## Key Design Decision: Which Commit?

The VFC contains `commit` and `diff_url` fields but not necessarily the pre-fix commit. We need to determine it from the diff metadata. Two approaches:
- **Approach A**: Use `vfc["commit"]` directly if it points to the vulnerable version
- **Approach B**: Parse the diff URL (`github.com/.../commit/...`) to extract the fix commit, then find the parent commit (last pre-fix version)

**Chosen**: Use VFC `commit` field as-is (it's already the vulnerable commit). If it points to the fix commit, we'll need git history traversal in Phase 2.5.

---

## Phase 1: Git-Repo Testbed Infrastructure

**Goal**: Clone vulnerable package repos at the right commits alongside existing testbeds.

### 1.1 Add config flags
- `GIT_TESTBED_ENABLED` (bool) — enable/disable git testbeds
- `GIT_TESTBED_SHALLOW_DEPTH` (int, default 50) — shallow clone depth
- `GIT_TESTBED_CACHE_DIR` (path) — where cloned repos are cached

### 1.2 Git repo resolver
- New class/function: `resolve_git_testbed(cve_id, vfcs_data)` 
- Parse VFC to extract: repo URL (from `diff_url`) + target commit (from `vfc["commit"]`)
- Clone shallowly if not already cached
- Return path like `git_testbeds/<pkg>@<short_sha>`

### 1.3 Integration with existing flow
- Update `_try_resolve_git_testbed()` in e2e script to use config flags
- Ensure git testbeds live alongside node_modules testbeds (no conflict)

**Validation**: Run resolver for arpping, verify it clones to the correct commit.

---

## Phase 2: Package Identification in Git Repos

**Goal**: Identify which files belong to the vulnerable package in a bare git repo.

### 2.1 Package directory detection
- Function: `_detect_git_repo_pkg(testbed, pkg_name)` 
- Scan testbed for directories/files matching `pkg_name` (e.g., `arpping/`, `arpping.js`)
- Also handle nested packages: `src/packages/arpping/`, `lib/arpping/`
- Return the package directory path (relative to testbed) or None

### 2.2 Package prefix builder
- Function: `_build_pkg_prefix_for_git(pkg_dir)` 
- Like `_detect_node_modules_pkg()` but for git repos
- Returns string like `arpping/` or `src/arpping/` — used for graph filtering

### 2.3 Edge scoping heuristic
- When js_call_graph runs on a bare git testbed, all edges come from the full repo
- Need to filter edges to only those involving the package's directory
- Use `pkg_dir` from Phase 2.2 to match `caller_file`/`callee_file` paths

**Validation**: For arpping git repo, verify we find `index.js` under the arpping directory and that edge filtering correctly limits to package-scoped edges.

---

## Phase 3: Graph Analyzer Adaptation for Git Testbeds

**Goal**: Update graph analysis pipeline to handle git-repo testbeds.

### 3.1 Graph generation adaptation
- In `_run_indexing()`: when testbed is a git repo (no `node_modules/`), use js_call_graph with package-dir awareness
- Pass the package directory from Phase 2.2 to js_call_graph so it can scope indexing
- Alternatively: run js_call_graph on just the package directory, not the full testbed

### 3.2 Node filtering for git repos
- Replace `_detect_node_modules_pkg()` → `_get_package_prefix()` (unified)
- For node_modules testbeds: prefix = `node_modules/<pkg>/` (current behavior)
- For git testbeds: prefix = package dir found in Phase 2.2 (e.g., `arpping/`)
- Update `_filter_graph()` to use the unified prefix

### 3.3 Symbol path normalization for BFS
- In `_bfs_taint_path()`: match adjacency list keys against matched method symbols
- For git testbeds: if caller is `arpping/index.js::fn_Arpping`, look up by `arpping/index.js` or `index.js`
- Build reverse map from bare filenames to full paths for ambiguity resolution

### 3.4 Matched method symbol normalization
- In graph matching: when resolving matched methods for git repos, ensure symbols include package directory prefix
- Current matched methods have `node_modules/arpping/` prefix — change to actual git repo path like `arpping/` or `index.js`

**Validation**: Run full pipeline on arpping git testbed. Verify:
- Graph has non-zero nodes from the correct package
- BFS finds taint flows (not just sinks)
- Dataflow output shows full path trace

---

## Phase 4: Commit Accuracy & Regression Prevention

**Goal**: Ensure we're analyzing the right version and no regressions occur.

### 4.1 Commit validation
- After cloning, verify HEAD matches expected commit
- If VFC `commit` points to fix commit, find parent via `git log --oneline | head -N`
- Add logging to show which commit was used for each CVE

### 4.2 Multi-CVE support
- Verify testbed resolution works for different packages/types:
  - Packages with own repos (arpping, arp-scan)
  - Packages in monorepos (e.g., a module inside `express/`)
  - npm-only packages with no git repo

### 4.3 Cleanup
- Add option to clean cached git testbeds (`--clean-git-testbeds`)
- Document testbed resolution order: git first → filesystem fallback

---

## Phase 5: Integration Testing & Documentation

**Goal**: End-to-end validation across multiple CVEs and user-facing docs.

### 5.1 Multi-CVE validation
Run on arpping, then try other CVEs to verify no regressions

### 5.2 Documentation updates
- Update `CLAUDE.md` with git testbed configuration options
- Document testbed resolution flow for future maintainers

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| VFC commit points to post-fix version | Git history traversal in Phase 2.5 |
| Some packages have no git repo | Fall back to existing filesystem testbed |
| js_call_graph on full monorepo is slow | Scope to package directory before indexing |
| Network dependency for cloning | Cache repos; graceful degradation |
