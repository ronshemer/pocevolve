# Data Flow Tracing via SCIP — Plan (directional)

## Architecture Overview

The PoCEvolve pipeline generates exploit code given a CVE and a package testbed. The model needs concrete data flow context to generate package-specific exploits. This plan adds that layer without changing existing pipeline behavior.

### Components

1. **Phase 1: Standalone Indexer** — takes a vulnerable package root directory, indexes it with SCIP-typescript, produces an in-package call graph. Independent of PoCEvolve; tested in isolation.

2. **Phase 2: Call Graph Logic** — built on top of the indexer's output. Finds which methods from the call graph appear in the CVE fix diff, then extracts tainted parameters and data flow paths from entry points to shell sinks. Still structural (not prompt-formatted).

3. **Phase 3: Pipeline Integration** — connects Phase 2's enriched data flows into the exploit generation pipeline. Wires analysis results to prompts, handles caching/fallback, measures improvement.

---

## Phase 1 — Standalone Indexer Component

### Purpose

Deliver a tested component that takes a vulnerable package root directory and outputs its in-package call graph via SCIP-typescript. Nothing more, nothing less. This is the data source for everything downstream.

### Input / Output

- **Input:** A single directory path (the already-generated testbed for the vulnerable package)
- **Output:** Structured in-package call graph — nodes are function/method definitions within the target package, edges are call relationships found inside the package tree. External dependencies (node_modules) and parent directories are excluded. Only the target scope matters.

### Design Notes

- SCIP is invoked as an external binary / library on a single directory
- The target is configured explicitly — it does not discover packages from node_modules or parent scopes
- Output format depends on the SCIP flavor being used (binary / proto output)
- A parsing + normalization layer sits between the raw SCIP output and the public API, so this module presents a clean abstraction regardless of how SCIP encodes its result

### Testing Strategy

- Test against known testbeds where data flow paths are known (e.g., arpping with its `ping()` → `exec()` pattern)
- Verify the call graph recovers these specific paths without including node_modules or parent-package edges
- Handle edge cases: packages with no callers, recursive functions, dynamically-typed code, CommonJS / ESM modules

---

## Phase 2a — Call Graph Logic (on top of the indexer)

### Purpose

Build analysis methods on top of the Phase 1 call graph that produce PoCEvolve-relevant results. This phase bridges the gap between a generic in-package graph and exploit-specific insights, but **still without connecting to the pipeline**. It is a self-contained analysis layer: call graph → enriched data flows.

### Core Methods

This phase implements two key capabilities:

**1. Diff-to-graph matching:** Given a commit diff (the patch for a CVE), identify which methods/entries in the call graph appear in the fix. The diff references method names, parameter names, and file paths — map those back to graph nodes to answer "what changed" in structural terms.

**2. Taint extraction from the call graph:** For each entry point identified (via the diff or otherwise), extract the tainted parameters and reconstruct data flow paths:
- Which parameters of a method carry untrusted values?
- How do those values propagate through intermediate calls?
- Where do they reach terminal sinks (shell commands)?

### Output

The phase produces an enriched representation — not just a raw call graph, but filtered results that answer "what entry points are relevant to this CVE and how does tainted data flow through them." The format is still structural (not yet prompt-formatted) so it can be independently tested.

### Testing Strategy (Phase 2a)

- **Diff-matching test:** give a known diff → verify the correct methods are identified in the call graph
- **Taint-extraction test:** give a package with known tainted paths → verify they are extracted correctly
- **Edge cases:** diffs that reference nothing in the graph, graphs with no terminal sinks, entry points with multiple branching flows

---

## Phase 2b — Pipeline Integration (final)

### Purpose

Connect Phase 2a's enriched data flows into the exploit generation pipeline. This is the plumbing layer: wire analysis results to prompts, handle caching/fallback, measure improvement. All logic from Phase 2a remains untouched — this phase only handles connectivity and presentation.

### Hook Point in Pipeline

Data flow analysis runs as an enrichment step within `generate_exploit()`, before prompt construction:

1. For each CVE entry being processed, pass the package source path to the indexer
2. Pass the CVE's diff to the Phase 2a analyzer to find relevant methods + tainted paths
3. Format enriched results for prompt injection
4. Inject into the exploit generation prompt alongside existing context
5. Ensure data flow context is available on retry attempts too — the model should see it every time, not just on attempt 1

### Prompt Injection Format — Direction

The data flow output needs to translate from a structured call graph into something the LLM can use operationally:
- Readable function signatures with parameter names
- Human-interpretable call chains showing how input reaches shell commands
- Clear highlighting of which parameters are tainted (the ones that carry user-controlled values)
- Practical guidance on how to call the vulnerable function from exploit code

The exact formatting approach is an implementation decision — the goal is to bridge between a structured graph and actionable exploit context for the model.

### Integration with Existing Feedback Loop

The retry mechanism currently sends back failed code + console output. With data flows available, this context should persist across retries so the model doesn't lose the concrete paths when re-attempting.

### Fallback — Graceful Degradation

Every step in the integration path must degrade silently:
- No SCIP? → no data flow section in prompt (same as current behavior)
- Indexer returns empty? → same as above
- Phase 2a analyzer finds nothing relevant? → same as above
- Parsing error? → log, skip, continue pipeline
- The system treats data flow enrichment as strictly optional — it never blocks exploit generation

### Performance Considerations

Each indexer invocation is a one-time cost per CVE. Results should be cached since source code doesn't change between runs. Re-run time after first pass should be negligible (cache hit only).

---

## File Changes

| Area | Phase | Change |
|---|---|---|
| `src/indexer/` | 1 | **NEW** — indexer module (all files) |
| `src/graph_analysis/` | 2a | **NEW** — diff-to-graph matching + taint extraction |
| `src/generator.py` | 2b | Add data flow enrichment hook in `generate_exploit()` and `_extract_exploit_context()` |
| `src/config.py` | 2b | Config flags for enabling/disabling data flow, cache path |
| Phase 1 tests | 1 | Isolated test suite (outside PoCEvolve integration) |
| Phase 2a tests | 2a | Diff-matching and taint-extraction tests |
| Phase 2b tests | 2b | Integration/smoke tests against full pipeline |

---

## Success Criteria

**Phase 1:**
- Indexer produces correct call graph for known test packages
- Handles missing SCIP gracefully with clear diagnostics
- Test coverage on the indexer's parsing and normalization layers

**Phase 2a:**
- Diff-to-graph matching correctly identifies modified methods across test CVEs
- Taint extraction recovers known data flow paths without excessive noise
- Component is usable as a library (graph → enriched flows) independent of pipeline

**Phase 2b:**
- Data flow enriches prompts when available, absent gracefully when not
- Model correctly uses data flow context (observable in generated responses)
- Primary metric: % of CVEs with at least 1 passing exploit (current baseline is 0%)
- Secondary: how many CVEs produce zero results from the indexer (indicates scope limitations)
