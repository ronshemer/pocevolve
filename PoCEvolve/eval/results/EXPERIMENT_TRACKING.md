# Full-dataset PoCEvolve experiment tracking

Dataset: `SecBench.js.PoCGen.vfc.quality154` (154 CVEs)

Model: `qwen36-local`

Generation attempts: up to 3

GEPA: disabled

| Configuration | Run | Passing CVEs | Rate | Result directory |
|---|---:|---:|---:|---|
| Direct LLM baseline, static analysis off | 1 | 50/154 | 32.47% | `eval/results/full-quality-run-1/` |
| Direct LLM baseline, static analysis off | 2 | 50/154 | 32.47% | `eval/results/full-quality-run-2/` |
| Direct LLM baseline, static analysis off | 3 | 57/154 | 37.01% | `eval/results/full-quality-run-3/` |
| Static context (entry points and target-method source) | 1 | 60/154 | 38.96% | `eval/results/direct_20261023_152730/` |
| Static context (entry points and target-method source) | 2 | 67/154 | 43.51% | `eval/results/static-analysis-run-2/` |
| Static context (entry points and target-method source) | 3 | 64/154 | 41.56% | `eval/results/static-analysis-run-3/` |

Baseline mean: 52.3/154 (34.0%). Static-context mean: 63.7/154 (41.3%), a difference of 11.3 CVEs or 7.4 percentage points. The three same-run comparisons favored static context by 10, 17, and 7 CVEs. Per-CVE outcomes varied substantially across runs, so treat this as evidence for this model, dataset, and attempt budget rather than a general result.

Each run directory includes `summary.json`, `dataset.txt`, `vfcs.predicted.json`, and `vfcs.generated.dataset.txt.jsonl` with prompts, generated outputs, and verifier logs. Generated npm testbeds, cloned vulnerable repositories, and LLM response caches are kept outside version control.
