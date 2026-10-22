# Phase 3: Git-Repo Testbeds — Eliminating node_modules Path Mismatch

## Problem

Graph matching fails across a broad class of CVEs because npm-installed packages in `node_modules/` produce SCIP symbols with full paths like `node_modules/arpping/index.js`, while VFC diff patches reference bare file paths like `index.js`. The existing three-tier matcher (symbol_map → fuzzy file+name → name-only) works for some cases but is inherently fragile when node_modules adds an arbitrary prefix.

**Architectural solution:** Use the actual git repository of each vulnerable package at the pre-fix commit as the testbed. This gives us a clean source-code-level directory where VFC diff file paths (e.g., `index.js`, `lib/core.js`) match exactly against SCIP-indexed symbols without any node_modules prefix.

## Data Analysis Summary

- **173 VFC entries** all have `vulnerability_fix_commit` with GitHub URLs
- **168 unique repos** (some CVEs reference the same repo)
- **165 direct commit refs** — format: `https://github.com/org/repo/commit/<hash>`
- **8 PR refs** — format: `https://github.com/org/repo/pull/<num>/commits/<hash>`
- 8 entries have no GitHub URL (different vulnerability tracking)

## Implementation Phases

---

## Phase 3.1: VFC Repo/Commit Extractor Utility

**Goal:** Given a VFC entry, extract the exact git repo URL and the pre-fix commit ref to check out.

### What it does

Takes a VFC entry dict → returns `(repo_url, checkout_ref, pkg_name)`.

For **direct commits** (`commit_type=commit`):
```
URL: https://github.com/haf-decent/arpping/commit/0db06723f8c3c73a5cc0829c667d45cba25ca44d
→ repo_url: git@github.com:haf-decent/arpping.git  (or https://...)
→ checkout_ref: 0db06723f8c3c73a5cc0829c667d45cba25ca44d
→ pkg_name: arpping
```

For **PR refs** (`commit_type=pull`):
```
URL: https://github.com/org/repo/pull/123/commits/abc123...
→ repo_url: from org/repo in URL
→ checkout_ref: the commit hash after /commits/
→ pkg_name: from vulnerable_package field
```

For **version-based** entries (`vulnerable_version` exists but no direct commit):
- Fall back to `git tag --contains` or `git ls-remote --tags` to find the closest tag matching `vulnerable_version`
- Checkout the parent commit of that tagged release (the last commit before the fix)

### Implementation details

**File:** `PoCEvolve/src/indexer/vfc_testbed.py` (new module alongside existing indexer modules)

```python
@dataclass
class RepoTestbedSpec:
    repo_url: str           # https://github.com/... or git@github.com:...
    pkg_name: str           # e.g. "arpping"
    checkout_ref: str       # commit hash, tag, or branch ref
    testbed_dir: Path       # where it will be / was cloned
    source_hash: str        # sha256 of vfc entry (for cache key)

def extract_testbed_spec(vfc_entry: dict) -> Optional[RepoTestbedSpec]:
    """Parse VFC entry → git repo spec. Returns None if no usable GitHub URL."""

def github_url_to_git(url: str) -> Optional[str]:
    """Convert https://github.com/org/repo/...  →  git@github.com:org/repo.git"""

def resolve_pre_fix_ref(org_repo: str, fix_commit: str, pkg_version: Optional[str]) -> str:
    """Given a fix commit, figure out what ref to check out BEFORE the fix.
    
    Strategy: the fix commit IS the pre-fix point if it's the merge/commit that
    introduced the vulnerability. But typically VFC commits ARE the fixes, so we
    want the parent of that commit (or last tagged release before the fix).
    
    Returns a git ref for checkout. May be:
    - The fix commit itself (if it's the vulnerable state)
    - Parent of the fix commit ('<hash>^')
    - A tag matching vulnerable_version
    """
```

**Key design decision:** Which commit to check out?

The VFC `vulnerability_fix_commit` points to the commit that **fixed** the vulnerability. We want the code state **before** that fix — i.e., the vulnerable version. The approach:

1. If `vulnerable_version` is available (e.g., "2.0.0"), try `git tag --list 'v*' | grep 2.0.0` or look for tags like `v2.0.0`.
2. If no matching tag, checkout the parent of the fix commit: `<fix_commit>^`.
3. For PR refs, the `/commits/<hash>` part is often the merge commit; take its parent relevant to the vulnerable branch.

**Fallback:** If git resolution fails, just use `checkout_ref = "<fix_commit>^"` and let git handle it (git will resolve ^ to the parent if available).

### Edge cases

- **Private repos:** VFC dataset contains only public GitHub repos — should be fine with no auth.
- **Deleted repos:** Handle 404 gracefully, log warning, fall back to existing testbed.
- **No git history (single commit repos):** Use the fix commit as-is.
- **Version tags that don't exist:** Fall back to parent of fix commit.

---

## Phase 3.2: Git Clone Manager

**Goal:** Given a `RepoTestbedSpec`, ensure the repo is cloned at the right ref into a testbed directory, handling caching and deduplication.

### Design

```python
GIT_TESTBED_ROOT = Path(__file__).parent.parent / "git_testbeds"  # .../secbenchjs/git_testbeds/

class GitTestbedManager:
    def __init__(self, cache_dir: Optional[Path] = None, shallow_depth: int = 50):
        self.cache_dir = cache_dir or GIT_TESTBED_ROOT
        self.shallow_depth = shallow_depth

    def ensure_specified(self, spec: RepoTestbedSpec) -> Path:
        """Clone (or reuse cached clone) and return the testbed directory path."""
        # Cache key: org_repo + ref → deterministic dir name
        repo_slug = spec.repo_url.rstrip('.git').split('/')[-1]
        cache_key = f"{repo_slug}@{spec.checkout_ref[:8]}"
        target_dir = self.cache_dir / cache_key
        
        if target_dir.exists() and self._is_correct_ref(target_dir, spec):
            return target_dir
        
        # Shallow clone for speed
        self._clone_repo(spec.repo_url, target_dir, spec.checkout_ref)
        return target_dir

    def _is_correct_ref(self, dir: Path, spec: RepoTestbedSpec) -> bool:
        """Check if the checked-out ref matches."""
        ...

    def _clone_repo(self, url: str, target: Path, ref: str):
        """Shallow clone at specific ref."""
        subprocess.run(['git', 'clone', '--depth', str(self.shallow_depth), url, str(target)])
        subprocess.run(['git', '-C', str(target), 'checkout', ref], check=True)
```

### Integration with existing testbeds

The current pipeline resolves testbed as: `args.testbed or ROOT / "testbed" / cve_id`

We add a **new resolution path**: if the VFC entry has a GitHub URL and no existing local testbed, create a git-based one. The new git testbed sits alongside existing testbeds in `secbenchjs/`:

```
secbenchjs/
├── vfcs.filtered.json
├── git_testbeds/          ← NEW directory
│   ├── arpping@0db06723/  ← shallow clone of haf-decent/arpping at that commit
│   ├── deeply@6eccb2f0/
│   └── ...
└── testbeds/              ← existing testbeds (may be empty or partial)
```

**Ordering:** When resolving a testbed for a CVE:
1. Use `args.testbed` if explicitly provided (user override wins)
2. Check if an existing local testbed exists at `secbenchjs/testbeds/<cve_id>` → use it
3. Look up git-based testbed in `secbenchjs/git_testbeds/` → use it
4. Fall back to the node_modules testbed (current behavior)

### Parallel cloning

For batch processing (`MINIBATCH_SIZE=3`), multiple CVEs may need clones simultaneously. The clone manager should:
- Use a file lock (`fcntl.flock`) on each cache directory during creation
- Allow parallel clones of different repos
- Never race on the same repo+ref pair

---

## Phase 3.3: Graph Analyzer Adaptation

**Goal:** Wire the git-based testbed into the indexing and analysis pipeline so SCIP indexes source code (not node_modules).

### Changes to `e2e_dataflow.py`

```python
# Current flow:
testbed = resolve_testbed(cve_entry)  # → node_modules/<pkg>/ or existing testbed
graph, nodes = parse_index(testbed)   # → SCIP of node_modules content

# New flow:
vfc_entry = load_vfc(cve_id)
git_testbed = ensure_git_testbed(vfc_entry) if git_testbed_available else None
testbed = git_testbed or resolve_testbed(cve_entry)  # ← prefer git testbed
graph, nodes = parse_index(testbed)                    # → SCIP of clean source
```

### Changes to indexing (`src/indexer/`)

The indexer already has `node_modules` exclusion hardcoded. With a clean git repo as testbed root:
- No `node_modules/` exists in the shallow clone (need to add `npm install` if runtime deps are needed, but for graph analysis we don't need them)
- SCIP naturally indexes only files within the package tree
- File paths in symbols match VFC diff paths exactly

**One concern:** The shallow clone may not have all dependency metadata (package.json with dependencies). For **graph analysis purposes this is fine** — we're analyzing one package's source, not running it. Dependencies are irrelevant to intra-package call graph.

### Changes to `parse_index()` in the pipeline

The testbed resolution logic currently returns a path into `node_modules/`. With git-based testbeds, it returns a clean directory containing just the vulnerable package's source tree. The parser and normalizer should work unchanged — they operate on the SCIP output which is now scoped to the right directory.

---

## Phase 3.4: Graph Matcher Path Resolution Fix

**Goal:** Ensure VFC diff file paths match cleanly against git-repo-scoped symbols without any prefix transformation.

### Current problem (solved by git testbeds)

With `node_modules/arpping/` as testbed, VFC diff says `index.js` but SCIP symbol is `node_modules/arpping/index.js` → mismatch.

**With git testbeds:** The testbed IS the package repo, so:
- VFC diff says `index.js` 
- SCIP symbol says `index.js`
- Match succeeds immediately at tier 1 (symbol_map) or tier 2 (exact file-path)

### Matcher changes needed

The existing `_match_node_by_file_and_name()` scoring already handles both exact match and containment matches. With clean paths, the simplest path forward:

1. **Tier 1 (symbol_map):** Will now work for files directly in the package root since VFC diff paths = SCIP symbol paths exactly.
2. **Tier 2 (fuzzy):** Already scored multi-candidate — no change needed, but scoring simplifies because file containment logic becomes trivial (both are bare filenames).
3. **Tier 3 (name-only):** Unchanged fallback.

**No code changes needed to the matcher itself** if we use git testbeds correctly — the matcher is already designed to be resilient. The real fix is at the testbed resolution level.

### One addition: diff-to-path normalization

For completeness, add a helper that extracts relative paths from VFC diffs and maps them into the source tree:

```python
def extract_diff_paths(vfc_entry: dict) -> list[str]:
    """Extract file paths from unified diff in VFC entry."""
    for change in vfc_entry.get('source_code_changes', []):
        diff = change.get('diff', '')
        # Parse +++/--- lines from unified diff
        for line in diff.splitlines():
            if line.startswith('+++ b/') or line.startswith('--- b/'):
                path = line[6:]  # strip prefix
                yield path
```

This is already implicit in the current flow (the diff reader already does this), so no new code needed.

---

## Phase 3.5: Validation

**Goal:** Run end-to-end on arpping and other CVEs to verify graph matching improvement and taint flow detection.

### Test plan

1. **Unit tests for extractor:**
   - `test_extract_direct_commit()` — parse direct commit URL → correct ref
   - `test_extract_pr_ref()` — parse PR URL → correct org/repo/ref
   - `test_url_to_git_conversion()` — https → git@github.com conversion
   - `test_invalid_url_fallback()` — non-GitHub URL → None

2. **Unit tests for clone manager:**
   - `test_ensure_specified_creates_dir()` — verify first run creates directory
   - `test_ensure_specified_reuses_cached()` — second call returns same path
   - `test_is_correct_ref_after_checkout()` — verify ref detection works

3. **Integration test — arpping:**
   ```bash
   python3 -B scripts/e2e_dataflow.py \
     --cve CVE-2024-XXXX \
     --testbed-type git  # or auto-detect
   ```
   Expected results:
   - Graph matches >1 method (vs current ~1-2)
   - VFC diff paths match at tier 1 (symbol_map) without fuzzy fallback
   - Taint flow recovers `ping()` → `exec()` pattern correctly
   - Matched methods have actual vulnerability context (not just require/import stubs)

4. **Integration test — deeply:**
   - Same verification, different package structure

5. **Regression test — existing testbeds:**
   - CVE entries with existing local testbeds still work (path 2 in resolution order)
   - Entries without GitHub URLs still work (fall back to node_modules path)

### Success criteria

| Metric | Before (node_modules) | Target (git testbed) |
|---|---|---|
| Tier-1 symbol_map matches per diff entry | ~0-2 | 5+ |
| Methods matched with non-zero relevance score | 1-3 | 5+ |
| Taint flows recovered with real vuln functions | <20% | 80%+ |
| Fuzzy fallback usage rate | ~70% | ~10% |

---

## Implementation Order & Dependencies

```
Phase 3.1 (extractor)      ← no dependencies, pure parsing
       ↓
Phase 3.2 (clone manager)  ← depends on 3.1
       ↓
Phase 3.3 (pipeline wiring)← depends on 3.2
       ↓
Phase 3.4 (matcher changes)← minimal changes, mostly validation only
       ↓
Phase 3.5 (validation)     ← all above complete
```

**Parallelization:** Phase 3.1 and the existing Phase 2a work can happen in parallel since they're independent.

### File structure after implementation

```
PoCEvolve/
├── secbenchjs/
│   ├── vfcs.filtered.json
│   ├── git_testbeds/             ← NEW (runtime-created, gitignore'd)
│   │   └── <repo>@<ref>/
│   └── testbeds/                 ← existing
├── src/
│   ├── indexer/
│   │   ├── vfc_testbed.py        ← NEW (Phase 3.1 + 3.2)
│   │   ├── config.py
│   │   ├── __init__.py
│   │   └── ...
│   ├── graph_analysis/
│   │   ├── graph_matcher.py      ← minor refinement (Phase 3.4)
│   │   ├── taint_flow.py
│   │   └── ...
│   └── config.py                 ← may add GIT_TESTBED_ENABLED flag
└── scripts/
    └── e2e_dataflow.py           ← testbed resolution update (Phase 3.3)
```

### Config additions

In `src/config.py`, add:
```python
GIT_TESTBED_ENABLED: bool = True      # Auto-use git testbeds when available
GIT_TESTBED_SHALLOW_DEPTH: int = 50   # Shallow clone depth
GIT_TESTBED_CACHE_DIR: Optional[Path] = None  # Defaults to secbenchjs/git_testbeds/
```

In `e2e_dataflow.py`, add CLI flag:
```bash
--testbed-source <auto|existing|git>  # Force testbed resolution strategy
```

### Git ignore additions

`secbenchjs/.gitignore` (create if doesn't exist):
```
git_testbeds/
```

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| Rate limiting on git clones | Medium | Shallow clone + caching; batch deduplication |
| Deleted/unreachable repos | Low (most are stable) | Graceful fallback to existing testbed |
| Missing package structure in shallow clone | Very low | We only need source files, not full history or tags |
| Git auth required for private repos | Very low | VFC dataset uses public repos |
| Shallow clone breaks `git rev-parse` checks | Low | Use `git ls-remote` instead of repo-local ref check |

### Technical risks specific to shallow clones

Shallow clones have limitations:
- No full history (we don't need it)
- `git describe` and tag lookup won't work → use `git ls-remote --refs` for version resolution before cloning
- `git rev-list` operations fail → avoid them, use `git cat-file` or `git verify-commit`

For the clone manager's `_is_correct_ref()` check on an already-cloned repo, use:
```bash
git -C <dir> rev-parse HEAD  # always works even in shallow clones
```

This compares the local HEAD against what we expect from the spec. If it matches, reuse; otherwise re-clone.

---

## Summary of what this solves

| Before (node_modules testbed) | After (git testbed) |
|---|---|
| SCIP paths: `node_modules/arpping/index.js` | SCIP paths: `index.js` |
| VFC diff paths: `index.js` | VFC diff paths: `index.js` |
| Path mismatch → fuzzy fallback → poor scores | Exact match → tier 1 symbol_map → clean results |
| Graph matcher is the bottleneck | Graph matcher works naturally |
| Taint flows miss real vulnerability functions | Taint flows trace from actual entry points |

This eliminates the root cause rather than adding more heuristics on top of a broken path. The graph matcher becomes a correct component again because its input (file paths) is consistent.
