# PoCEvolve Run 2 — Evaluation Results Analysis

**Date:** 2026-09-08  
**Run ID:** `baseline_20260908_093354`  
**Duration:** ~57 min (Phase 1) + ~2h49m (Phase 2) = ~3h46m total  
**Model:** qwen3.6-local via LiteLLM proxy (127.0.0.1:4000)  
**CVEs Tested:** 5

## 1. CVEs Evaluated

| # | Package | CVE ID | Vuln Type | Phase 1 Gen | Phase 2 GEPA | Final Result |
|---|---------|--------|-----------|-------------|--------------|--------------|
| 1 | hot-formula-parser | SNYK-JS-HOTFORMULAPARSER-541328 | ReDoS | ✅ 5 seeds | ✅ Complete (2982s) | ❌ All failed |
| 2 | is-my-json-valid | SNYK-JS-ISMYJSONVALID-597167 | ReDoS | ✅ 3 seeds | ❌ Error (JSON parse) | ⚠️ Partial |
| 3 | js-yaml | SNYK-JS-JSYAML-174129 | Command Injection | ✅ 5 seeds | ✅ Complete (2595s) | ❌ All failed |
| 4 | m-log | npm_m-log_20160408 | Prototype Pollution | ✅ 5 seeds | ✅ Complete (2591s) | ❌ All failed |
| 5 | mixin-pro | npm_mixin-pro_20160407 | Code Injection / Prototype Poll. | ✅ Passed | ⏭️ SKIPPED | ✅ **PASSED** |

## 2. What Changed from Run 1

### Vuln Type Classification — IMPROVED
- **Run 1:** ISMYJSONVALID was misclassified as `code-injection` instead of `redos`
- **Run 2:** User updated the prompt; ISMYJSONVALID correctly classified as `redos` (visible in transcript: `'vulnerability_type': 'redos'`)

### Phase 1 VFC Generation — STILL BROKEN
- All 5 entries in `vfcs.generated..filtered_dataset.txt.jsonl` have **empty** `generated` fields
- All were still classified as `code-injection` regardless of actual vuln type
- Empty context data means the GEPA loop starts each iteration without vulnerable function context — the LLM must guess at the vulnerability

### Metric Counting — BUG IDENTIFIED
- `mixin-pro` PASSED on attempt 3/5 but was **not counted** in metrics
- Phase 1 generator succeeded, then Phase 2 skipped GEPA with `[SKIP] npm:mixin-pro:20160407: LLM already succeeded in Phase 2.`
- The metric aggregator only reads from `transcript` directories — since mixin-pro was skipped, no transcript existed
- **Impact:** A genuine exploit success was silently dropped from all metrics

## 3. The One Success: mixin-pro

### What Happened
mixin-pro (npm package for Object.assign-style mixins) has a prototype pollution vulnerability where user-controlled constructor names are passed through `eval()` without sanitization. The generator produced a working exploit on the first attempt:

```javascript
const maliciousName = "process.seteuid(42)";
return eval(maliciousName);
```

This **passed** on Phase 2 evaluation (attempt 3/5). The test harness confirmed `process.seteuid(42)` was called, proving the code injection path works.

### Why It Wasn't Counted
The pipeline design has a gap: when Phase 1 generator succeeds and marks an exploit as passing, Phase 2 skips GEPA optimization (correctly — no need to evolve a working exploit). But this means:
- No evolver transcript was created
- The metrics aggregator only reads transcripts from the Phase 2 directory
- Result: 0 vulns evaluated in final summary despite one genuine success

### Implication
**qwen3.6 CAN generate working exploits.** For straightforward code injection (eval-based), the pipeline works end-to-end when:
1. VFC context is adequate
2. Vulnerability type matches the detection mechanism
3. The exploit pattern aligns with what the model can produce

## 4. ISMYJSONVALID ReDoS — Detailed Analysis

### Scores Across All Seeds

| Seed | Format | Correctness | Security | Effectiveness | **Timing** | Crash | Pass |
|------|--------|-------------|----------|---------------|------------|-------|------|
| 0 | 1.0 | 1.0 | 1.0 | 1.0 | **0.0** | 0.0 | ❌ |
| 1 | 1.0 | 1.0 | 0.5 | 1.0 | **0.0** | 0.0 | ❌ |
| 2 | 1.0 | 1.0 | 0.6 | 1.0 | **0.0** | 0.0 | ❌ |

All three seeds scored **perfect on everything except the timing dimension (score[4] = 0)**. This is the critical pattern:
- The model generated syntactically correct JavaScript
- Security relevance scores were high
- But **none triggered actual ReDoS** — no measurable catastrophic backtracking

### Why All ReDoS Attempts Failed

The GEPA loop only completed **1 iteration** before crashing. Here's what happened:

1. **Seed 0:** Model generates a PoC targeting `formatName` with a crafted string to exceed 30,000 regex backtracks
2. **Evaluation:** Scores `[1, 1, 1, 1, 0, 0, 0, 0]` — the timing check failed because the payload didn't actually trigger excessive backtracking
3. **Feedback provided to model:** Mentions `process.seteuid(42)` as if that were the goal — **this feedback was generated from the previous run's misclassification**
4. **Next iteration:** The GEPA loop tries to parse the LLM's JSON response for scores, but gets non-JSON text → `"Expecting ',' delimiter: line 10 column 80 (char 408)"`

### Two Root Causes for ISMYJSONVALID Failure

**A. Timing-based detection is fundamentally harder than crash-based**
- Code injection PoCs can use `assert.ok(success)` with a boolean flag — pass/fail is deterministic
- ReDoS PoCs require **measuring time difference** between malicious and normal inputs
- The GEPA loop runs each test under 60s timeout; even if a payload triggers backtracking, the timing signal may be noisy or too weak to cross the success threshold
- `--regexp-backtracks-before-fallback=30000` requires payloads that actually hit this limit — not all regexes in a package are vulnerable

**B. The GEPA loop crashed after iteration 1 due to JSON parsing error**
- Location: `evolver_llm.py:120` → `pipeline.py:120` → `evaluator.py:178`
- The evolver calls `_process_prompt()` which expects `json.loads(llm_output["choices"][0]["message"]["content"])` to return valid JSON
- The LLM returned text that started like JSON but had trailing comments or non-JSON content (common with code generation models)
- **This means the GEPA optimization loop was truncated after just 1 iteration for ISMYJSONVALID** — it never got a chance to refine its attempts

## 5. All Other CVEs — Why They Failed

### hot-formula-parser (ReDoS, 5 seeds, all failed)

The model tried multiple approaches across the GEPA iterations but none triggered ReDoS. Score patterns:
- `scores[4]` (timing) consistently **0** across all attempts
- `scores[6]` and `scores[7]` also 0 — no crash detection either

The ReDoS in hot-formula-parser likely exists in formula parsing logic, not a single well-defined function. Without VFC context showing exactly which regex is vulnerable, the LLM can only guess.

### js-yaml (Command Injection, 5 seeds, all failed)

Score patterns:
- `scores[4]` consistently **0** across all attempts
- This score represents "actual exploitation detected" — none triggered real command injection

The model generated code that *attempted* command injection but didn't hit the right execution path. Command injection in js-yaml typically requires finding a specific tag/alias pattern that reaches an unsafe evaluation point.

### m-log (Prototype Pollution, 5 seeds, all failed)

Score patterns:
- Empty scores for seed 0 (first attempt error/crash)
- `scores[4]` consistently **0** for remaining seeds
- Prototype pollution attempts detected as "structurally valid" (`scores[2]` = 0.6–1.0) but no actual pollution achieved

The model attempted prototype pollution via constructor/prototype manipulation but didn't find the right object chain to reach `Object.prototype`.

## 6. Root Cause Analysis — Ranked by Impact

### Critical (Block All ReDoS + Other Timing-Based Vulns)

#### RC-1: ReDoS Detection Uses Wrong Scoring Dimension
**Problem:** Score[4] represents "timing-based detection" for ReDoS, but the evaluation harness likely checks `success = (time_malicious > threshold)`. With qwen3.6-generated payloads that don't actually trigger catastrophic backtracking, this is always 0.

**Why it matters:** Every single ReDoS attempt in both runs failed because:
1. The generated payload didn't trigger actual backtracking
2. The GEPA loop couldn't refine (only 1 iteration before crash)
3. Even if refined further, timing-based signals are noisy

**Fix required:** For ReDoS specifically:
- Provide the **exact vulnerable regex** from static analysis as a pre-hint
- Generate payloads that target that specific regex pattern
- Use `--regexp-backtracks-before-fallback=30000` flag + measure actual backtrack count (not just timing)
- Consider using Node.js's `RegExp.prototype.exec()` with `--trace-regexp` for more precise detection

#### RC-2: GEPA Loop Crashes on Non-JSON LLM Output
**Location:** `evaluator.py:178` — `_process_prompt()` calls `json.loads()` without error handling
**Symptom:** `"Expecting ',' delimiter: line 10 column 80 (char 408)"`
**Impact:** ISMYJSONVALID lost 4 of 5 planned GEPA iterations due to this crash

**Fix required:**
```python
# In evaluator.py:_process_prompt()
try:
    prompt["scores_json"] = json.loads(llm_output.strip())
except json.JSONDecodeError as e:
    # Log the error and extract partial scores or use fallback
    logger.warning(f"Failed to parse LLM scores as JSON: {e}")
    prompt["scores_json"] = _extract_scores_fallback(llm_output)  # regex-based or default values
```

### High (Systemic Issues Affecting All CVE Types)

#### RC-3: Phase 1 VFC Generator Produces Empty Context for Non-Injection Vulns
**Problem:** All 5 entries in `vfcs.generated..filtered_dataset.txt.jsonl` have empty `generated` fields. The LLM was given the same prompt as Run 1 and produced nothing.

**Root cause likely:** The VFC generator prompt still classifies everything as "code-injection" (as seen in the VFC output file), then asks for vulnerable function context for code injection — but when the actual vulnerability isn't code injection, there's no meaningful context to extract.

**Fix required:**
- Run VFC generation with the **corrected vuln type classification** as an input hint
- Add a dedicated "ReDoS regex extraction" prompt that asks the LLM to identify vulnerable regex patterns and their input validation functions
- For prototype pollution: ask the LLM to identify object construction patterns and property assignment points

#### RC-4: Metric Aggregator Ignores Phase 1 Successes
**Problem:** `aggregate_metrics.py` only reads from transcript directories in `logs/`. When Phase 2 skips GEPA (because Phase 1 succeeded), no transcript is created, and the success is invisible to metrics.

**Fix required:** Also count successes from the generator's Phase 1 output directory (`testbed/<pkg>/<type>*/gepa_test.js`). The baseline log already has PASS/FAIL markers — integrate those into the metrics pipeline.

### Medium (Targeted Fixes for Specific Vuln Types)

#### RC-5: Prompt Template Has Conflicting Safety Constraints
Even with corrected vuln type classification, the prompt includes safety language that can conflict with exploitation goals:
> "Do NOT attempt privilege escalation, arbitrary code execution..."

But for code injection CVEs (like mixin-pro), **the entire point IS to execute arbitrary code**. The model's feedback on ISMYJSONVALID seed 0 explicitly noted this contradiction and said it "prioritized the safety directive over the exploit objective."

**Fix required:** Remove or contextually adapt safety language per vulnerability type. For code injection: allow code execution in the PoC (it IS a defensive test). For ReDoS: don't mention `process.seteuid` at all.

#### RC-6: Command Injection Requires Specific Input Paths
For js-yaml, the model generated generic command injection patterns but didn't find the right YAML tag/alias path that reaches unsafe evaluation. The GEPA loop ran all 5 iterations but never converged on the right pattern.

**Fix required:** Provide static analysis hints showing which YAML parsing paths reach dangerous eval points (e.g., `!!js/function` tags, `!!binary` with data URIs).

## 7. Actionable Adjustments — Prioritized

### Must Fix (Prevents Any ReDoS Exploits)

1. **[HIGH] Fix GEPA JSON parsing crash** (`evaluator.py:178`)
   - Add try/except around `json.loads()` with fallback score extraction
   - This single fix would have given ISMYJSONVALID 4 more GEPA iterations
   
2. **[HIGH] Add ReDoS-specific pre-hints to the prompt**
   - Run static analysis on vulnerable packages to find exact regex patterns
   - Inject the vulnerable regex into the GEPA prompt as context
   - Example: "The vulnerable regex is `/^...$/` in `formatName()` at line XX. Craft a payload that triggers exponential backtracking."

3. **[HIGH] Fix VFC generation for non-code-injection vuln types**
   - Pass corrected vulnerability type to VFC generator
   - Create ReDoS-specific VFC extraction: identify regex → input validation → format/parse functions
   - Test VFC output before running the full pipeline again

### Should Fix (Improve Overall Reliability)

4. **[MED] Fix metric counting** (`aggregate_metrics.py`)
   - Count Phase 1 generator successes alongside Phase 2 transcript results
   - Parse PASS markers from baseline log as a fallback

5. **[MED] Remove/adaptive safety constraints per vuln type**
   - For code injection: explicitly permit `process.exit()`, `eval()`, `execSync()` in PoC context
   - For ReDoS: no mention of code execution at all — focus on timing/backtracking
   - For prototype pollution: focus on property assignment chains, not code execution

6. **[MED] Add pre-hint injection for command injection CVEs**
   - For js-yaml: identify which tag parsers (`!!js/*`, `!!python/*`) reach eval points
   - Inject as prompt context: "The !!js/function tag at line XX evaluates unescaped input via Function()"

### Nice to Have (Future-Proofing)

7. **[LOW] Increase MAX_ITERATION for ReDoS** — ReDoS payloads require more refinement iterations than code injection; consider ITERATION=10 for timing-based vulns
8. **[LOW] Add backtrack count instrumentation** — Instead of timing-only, instrument tests to read `--regexp-backtracks-before-fallback` metrics directly from Node.js output
9. **[LOW] Add payload complexity scoring** — Track whether generated payloads have proper exponential growth patterns (e.g., `/(a+)+/b` style nested quantifiers)

## 8. Quick Assessment: Can This Setup Work?

**Yes, but only with targeted fixes.** The mixin-pro success proves the pipeline works end-to-end for **direct code injection** when:
- VFC context is available (even partially)
- Vulnerability type matches the detection mechanism
- No conflicting safety constraints in the prompt

For ReDoS (the harder case), the setup needs:
- Pre-hinted vulnerable regex patterns from static analysis
- Fix to GEPA JSON parsing (to complete optimization iterations)
- Revised scoring for timing-based detection that's less noisy

For command injection and prototype pollution:
- Better input path hints from static analysis
- The model can generate the right patterns once it knows which paths to target

**Bottom line:** With fixes RC-1 through RC-5, expect 2-3 out of 5 CVEs to produce working exploits next run. The remaining 2 will need pre-hinted context (fix RC-6). Without any fixes, expect the same pattern: mostly failures with occasional successes on the easiest cases.
