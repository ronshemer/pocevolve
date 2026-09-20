#!/usr/bin/env python3
"""aggregate_metrics.py — Extract and summarize evaluation metrics from transcript runs.

Produces structured per-vuln and aggregated metrics for before/after comparison.

Usage:
    # Single run aggregation
    python3 aggregate_metrics.py --logs-dir PoCEvolve/logs --output results/metrics.json

    # Compare two runs (baseline vs improvement)
    python3 aggregate_metrics.py \
        --baseline results/baseline_metrics.json \
        --improvement results/improvement_metrics.json \
        --output results/comparison.csv

    # All-at-once (auto-detects all transcript runs)
    python3 aggregate_metrics.py --logs-dir PoCEvolve/logs --all-runs --output results/all_metrics.json
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path


# ─── Vulnerability type classification ────────────────────────────────────────

CATEGORIES = ["code-injection", "command-injection", "path-traversal",
              "prototype-pollution", "redos"]


def classify_vuln(datapoint: dict) -> str | None:
    """Return vulnerability category from a transcript or datapoint."""
    # Try transcript's attempts > seed_prompts first
    for attempt in datapoint.get("attempts", []):
        for sp in attempt.get("seed_prompts") or []:
            if v := sp.get("vulnerability_type"):
                return v.lower()

    # Fall back to datapoint-level
    if (vt := datapoint.get("generated", {}).get(
            "potential_vulnerability", {}).get("potential_vulnerability_type")):
        return vt.lower().replace(" ", "-")
    if vt := datapoint.get("vulnerability_type"):
        return vt.lower().replace(" ", "-")

    return None


# ─── Per-vuln metrics ────────────────────────────────────────────────────────

def compute_per_vuln_metrics(transcript: dict) -> dict | None:
    """Extract per-vulnerability metrics from a single transcript entry."""
    vuln_id = transcript.get("id", "")
    if not vuln_id:
        return None

    attempts = transcript.get("attempts") or []
    if not attempts:
        # No attempts yet — partial/incomplete run
        return {
            "vuln_id": vuln_id,
            "status": "incomplete",
            "passed": False,
            "total_attempts": 0,
            "total_iterations": 0,
            "avg_score": None,
            "max_score": None,
            "min_score": None,
            "median_score": None,
            "scores_collected": [],
            "vulnerability_type": classify_vuln(transcript),
            "status_detail": "no attempts recorded",
        }

    total_attempts = 0
    total_iterations = len(attempts)
    all_scores = []
    passed = False
    success_attempt_idx = None

    for i, attempt in enumerate(attempts):
        seed_prompts = attempt.get("seed_prompts") or []
        total_attempts += len(seed_prompts)

        for sp in seed_prompts:
            if sp.get("exploit_result"):
                passed = True
                if success_attempt_idx is None:
                    success_attempt_idx = i

            score = sp.get("avg_score")
            if score is not None:
                all_scores.append(float(score))

            raw_scores = sp.get("scores", [])
            if isinstance(raw_scores, list):
                for s in raw_scores:
                    if isinstance(s, (int, float)):
                        all_scores.append(float(s))
                    elif isinstance(s, dict) and "score" in s:
                        all_scores.append(float(s["score"]))

    scores_collected = sorted(all_scores) if all_scores else []

    # Compute score stats
    avg_score = sum(scores_collected) / len(scores_collected) if scores_collected else None
    max_score = max(scores_collected) if scores_collected else None
    min_score = min(scores_collected) if scores_collected else None
    median_score = _median(scores_collected)

    status_detail = "success" if passed else "failed"
    if success_attempt_idx is not None:
        status_detail += f" (attempt {success_attempt_idx + 1})"

    return {
        "vuln_id": vuln_id,
        "status": "completed" if transcript.get("error") else ("completed_with_error" if "error" in transcript else "unknown"),
        "passed": passed,
        "total_attempts": total_attempts,
        "total_iterations": total_iterations,
        "success_attempt_index": success_attempt_idx,
        "avg_score": round(avg_score, 4) if avg_score is not None else None,
        "max_score": round(max_score, 4) if max_score is not None else None,
        "min_score": round(min_score, 4) if min_score is not None else None,
        "median_score": round(median_score, 4) if median_score is not None else None,
        "scores_collected_count": len(scores_collected),
        "vulnerability_type": classify_vuln(transcript),
        "status_detail": status_detail,
        # Timing from transcript-level fields
        "timers": attempt.get("timers", {}) if attempts else {},
        # Model info
        "model": transcript.get("model"),
    }


def _median(sorted_values: list) -> float | None:
    if not sorted_values:
        return None
    n = len(sorted_values)
    if n % 2 == 1:
        return sorted_values[n // 2]
    return (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2


# ─── Aggregated metrics ──────────────────────────────────────────────────────

def compute_aggregated(per_vuln: list) -> dict:
    """Compute aggregate statistics from per-vuln metrics."""
    completed = [v for v in per_vuln if v["status"] == "completed"]
    all_vulns = per_vuln  # include incomplete
    total_vulns = len(all_vulns)
    completed_count = len(completed)

    # Pass/fail counts
    passed = sum(1 for v in completed if v["passed"])
    failed = completed_count - passed

    # Per-category stats
    cat_passed = Counter()
    cat_total = Counter()
    cat_scores = defaultdict(list)
    for v in completed:
        vt = v.get("vulnerability_type") or "unknown"
        cat_total[vt] += 1
        if v["passed"]:
            cat_passed[vt] += 1
        if v.get("avg_score") is not None:
            cat_scores[vt].append(v["avg_score"])

    # All scores pooled
    all_avg_scores = [v["avg_score"] for v in completed if v.get("avg_score") is not None]
    all_max_scores = [v["max_score"] for v in completed if v.get("max_score") is not None]
    all_min_scores = [v["min_score"] for v in completed if v.get("min_score") is not None]

    # Total LLM calls estimate (approximation: attempts × average per-attempt prompts)
    total_attempts_sum = sum(v["total_attempts"] for v in completed)

    # Iterations to success distribution
    success_attempts_list = [v["success_attempt_index"] for v in completed if v.get("success_attempt_index") is not None]

    result = {
        "run_summary": {
            "total_vulns": total_vulns,
            "completed": completed_count,
            "incomplete_or_error": total_vulns - completed_count,
            "passed": passed,
            "failed": failed,
            "overall_pass_rate": round(passed / completed_count * 100, 2) if completed_count else 0,
        },
        "per_category": {},
        "score_statistics": {},
        "work_distribution": {
            "total_attempts_across_all": total_attempts_sum,
            "avg_attempts_per_vuln": round(total_attempts_sum / completed_count, 2) if completed_count else 0,
            "max_attempts_single_vuln": max((v["total_attempts"] for v in completed), default=0),
            "min_attempts_single_vuln": min((v["total_attempts"] for v in completed), default=0),
        },
        "success_timings": {},
    }

    # Per-category
    for cat in CATEGORIES:
        total = cat_total.get(cat, 0)
        p = cat_passed.get(cat, 0)
        result["per_category"][cat] = {
            "total": total,
            "passed": p,
            "failed": total - p,
            "pass_rate": round(p / total * 100, 2) if total else 0,
            "avg_score": round(sum(cat_scores[cat]) / len(cat_scores[cat]), 4) if cat_scores[cat] else None,
        }

    # Score statistics (across all categories)
    if all_avg_scores:
        result["score_statistics"] = {
            "mean_avg_score": round(sum(all_avg_scores) / len(all_avg_scores), 4),
            "median_avg_score": round(_median(sorted(all_avg_scores)), 4),
            "max_avg_score": round(max(all_avg_scores), 4),
            "min_avg_score": round(min(all_avg_scores), 4),
            "score_std_dev": _stddev(all_avg_scores),
        }

    # Success timings (how many iterations until success)
    if success_attempts_list:
        result["success_timings"]["avg_iterations_to_success"] = round(
            sum(success_attempts_list) / len(success_attempts_list), 2)
        result["success_timings"]["max_iterations_needed"] = max(success_attempts_list)
        result["success_timings"]["min_iterations_needed"] = min(success_attempts_list)

    return result


def _stddev(values: list) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return variance ** 0.5


# ─── Per-vuln detail records ─────────────────────────────────────────────────

def per_vuln_detail(per_vuln: list) -> list[dict]:
    """Format per-vuln metrics for CSV output."""
    rows = []
    for v in sorted(per_vuln, key=lambda x: x["vuln_id"]):
        scores_raw = v.get("scores_collected_count", 0)
        timers = v.get("timers", {})
        row = {
            "vuln_id": v["vuln_id"],
            "status": v["status"],
            "passed": v["passed"],
            "vulnerability_type": v.get("vulnerability_type") or "",
            "total_attempts": v["total_attempts"],
            "total_iterations": v["total_iterations"],
            "avg_score": v.get("avg_score"),
            "max_score": v.get("max_score"),
            "min_score": v.get("min_score"),
            "median_score": v.get("median_score"),
            "success_attempt_index": v.get("success_attempt_index"),
            "scores_collected_count": scores_raw,
            "model": v.get("model") or "",
        }
        # Flatten timers if present
        for k, val in timers.items():
            row[f"timer_{k}"] = val
        rows.append(row)
    return rows


# ─── Transcript loading ──────────────────────────────────────────────────────

def load_transcripts(logs_dir: str) -> list[dict]:
    """Load all transcript.json files from the logs directory tree."""
    transcripts = []
    base = Path(logs_dir)

    for json_file in base.rglob("transcript.json"):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
            data["_source"] = str(json_file)
            transcripts.append(data)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[WARN] Skipping {json_file}: {e}", file=sys.stderr)

    return transcripts


def load_generated_exploits(logs_dir: str) -> dict:
    result = {}
    base = Path(logs_dir)

    for f in base.glob("vfcs.generated*.jsonl"):
        try:
            with open(f, "r") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Normalize raw ID and testbed_dir (e.g., npm:m-log:20160408 -> npm_m-log_20160408)
                    raw_id = entry.get("testbed_dir", "") or entry.get("id", "")
                    vid = raw_id.replace(":", "_")
                    if not vid:
                        continue

                    result[vid] = {
                        "generation_time": entry.get("generation_time"),
                        "has_generated_exploits": "generated_exploits" in entry,
                        "vulnerability_type": classify_vuln(entry),
                    }

                    prompts = entry.get("generated_exploits") or []
                    if prompts:
                        result[vid]["phase1_pass_count"] = sum(
                            1 for p in prompts if isinstance(p, dict) and p.get("exploit_result"))
                        result[vid]["phase1_total"] = len(prompts)

        except IOError:
            pass

    return result


# ─── Main aggregation logic ──────────────────────────────────────────────────

def aggregate_single(logs_dir: str, dataset_list: str | None = None) -> dict:
    print(f"Loading transcripts from {logs_dir}...", file=sys.stderr)
    transcripts = load_transcripts(logs_dir)
    print(f"Found {len(transcripts)} transcripts", file=sys.stderr)

    # Pass logs_dir so it searches inside the run folder!
    generated = load_generated_exploits(logs_dir)

    # Track which vulns have a Phase 2 transcript (to find Phase 1-only successes)
    transcript_vids: set[str] = set()

    per_vuln = []
    for t in transcripts:
        metrics = compute_per_vuln_metrics(t)
        if metrics is None:
            continue

        # Enrich with generated data if available
        vuln_id = metrics["vuln_id"]
        transcript_vids.add(vuln_id)
        if vuln_id in generated:
            g = generated[vuln_id]
            metrics["generation_time"] = g.get("generation_time")
            if g.get("has_generated_exploits"):
                metrics["generated_exploits_available"] = True
                # Phase 1 had exploits — note count for awareness
                if g.get("phase1_pass_count"):
                    metrics["phase1_pass_count"] = g["phase1_pass_count"]

        per_vuln.append(metrics)

    # Add vulns that succeeded in Phase 1 but had no Phase 2 transcript (e.g. skipped)
    for vid, g in generated.items():
        if vid in transcript_vids:
            continue
        pass_count = g.get("phase1_pass_count", 0) or 0
        # Only count as completed if at least one exploit passed in Phase 1
        per_vuln.append({
            "vuln_id": vid,
            "status": "completed",
            "passed": pass_count > 0,
            "total_attempts": g.get("phase1_total", 0) or 0,
            "total_iterations": 0,
            "success_attempt_index": None,
            "avg_score": None,
            "max_score": None,
            "min_score": None,
            "median_score": None,
            "scores_collected_count": 0,
            "vulnerability_type": g.get("vulnerability_type"),
            "status_detail": "phase1_success" if pass_count > 0 else "phase1_no_pass",
            "generation_time": g.get("generation_time"),
            "generated_exploits_available": g.get("has_generated_exploits", False),
        })

    aggregated = compute_aggregated(per_vuln)
    aggregated["per_vuln"] = per_vuln
    aggregated["source_dir"] = logs_dir
    aggregated["transcript_count"] = len(transcripts)
    aggregated["generated_exploit_count"] = sum(1 for v in per_vuln if v.get("generated_exploits_available"))

    return aggregated


def compare_runs(baseline: dict, improvement: dict) -> dict:
    """Produce before/after comparison."""
    b_summary = baseline["run_summary"]
    i_summary = improvement["run_summary"]

    b_cat = baseline.get("per_category", {})
    i_cat = improvement.get("per_category", {})

    comparison = {
        "comparison_type": "baseline_vs_improvement",
        "summary": {
            "overall_pass_rate": {
                "baseline": f"{b_summary['overall_pass_rate']:.1f}%",
                "improvement": f"{i_summary['overall_pass_rate']:.1f}%",
                "delta_pct_points": round(i_summary["overall_pass_rate"] - b_summary["overall_pass_rate"], 2),
            },
            "total_passed": {
                "baseline": b_summary["passed"],
                "improvement": i_summary["passed"],
                "delta": i_summary["passed"] - b_summary["passed"],
            },
            "total_vulns_evaluated": {
                "baseline": b_summary["completed"],
                "improvement": i_summary["completed"],
            },
        },
        "per_category": {},
        "score_comparison": {},
    }

    # Per-category comparison
    all_cats = set(list(b_cat.keys()) + list(i_cat.keys()))
    for cat in sorted(all_cats):
        bc = b_cat.get(cat, {})
        ic = i_cat.get(cat, {})
        b_pass = bc.get("pass_rate", 0) or 0
        i_pass = ic.get("pass_rate", 0) or 0

        comparison["per_category"][cat] = {
            "total": {
                "baseline": bc.get("total", 0),
                "improvement": ic.get("total", 0),
            },
            "passed": {
                "baseline": bc.get("passed", 0),
                "improvement": ic.get("passed", 0),
            },
            "pass_rate": {
                "baseline": f"{b_pass:.1f}%",
                "improvement": f"{i_pass:.1f}%",
                "delta_pct_points": round(i_pass - b_pass, 2),
            },
            "avg_score": {
                "baseline": bc.get("avg_score"),
                "improvement": ic.get("avg_score"),
            },
        }

    # Score statistics comparison
    b_scores = baseline.get("score_statistics", {})
    i_scores = improvement.get("score_statistics", {})

    if b_scores and i_scores:
        for key in ["mean_avg_score", "median_avg_score"]:
            bv = b_scores.get(key)
            iv = i_scores.get(key)
            if bv is not None and iv is not None:
                comparison["score_comparison"][key] = {
                    "baseline": round(bv, 4),
                    "improvement": round(iv, 4),
                    "delta": round(iv - bv, 4),
                }

    return comparison


# ─── CSV output for per-vuln results ────────────────────────────────────────

def write_csv(per_vuln: list, output_path: str):
    """Write per-vuln metrics as CSV."""
    if not per_vuln:
        print("[WARN] No per-vuln data to write", file=sys.stderr)
        return

    fieldnames = ["vuln_id", "status", "passed", "vulnerability_type",
                  "total_attempts", "total_iterations", "avg_score",
                  "max_score", "min_score", "median_score",
                  "success_attempt_index", "scores_collected_count", "model"]

    # Add timer columns dynamically
    timer_keys = set()
    for v in per_vuln:
        for k in (v.get("timers") or {}).keys():
            timer_keys.add(f"timer_{k}")
    fieldnames.extend(sorted(timer_keys))

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in per_vuln_detail(per_vuln):
            writer.writerow(row)

    print(f"[DONE] CSV written to {output_path} ({len(per_vuln)} rows)", file=sys.stderr)


# ─── CLI entry point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Aggregate PoCEvolve evaluation metrics from transcripts")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--logs-dir", help="Directory containing transcript.json files")
    group.add_argument("--baseline", help="Path to baseline metrics JSON (for comparison)")
    group.add_argument("--improvement", help="Path to improvement metrics JSON (for comparison)")

    parser.add_argument("--output", "-o", required=True, help="Output file path")
    parser.add_argument("--csv-output", help="Also write per-vuln CSV to this path")
    parser.add_argument("--dataset-list", help="Dataset list file for filtering")
    parser.add_argument("--all-runs", action="store_true",
                        help="Auto-detect and aggregate all runs in logs-dir into one file")
    parser.add_argument("--format", choices=["json", "csv"], default="json",
                        help="Output format (default: json)")

    args = parser.parse_args()

    if args.baseline and args.improvement:
        # Comparison mode
        print("Loading baseline metrics...", file=sys.stderr)
        with open(args.baseline) as f:
            baseline = json.load(f)
        print("Loading improvement metrics...", file=sys.stderr)
        with open(args.improvement) as f:
            improvement = json.load(f)

        comparison = compare_runs(baseline, improvement)

        # Write JSON comparison
        with open(args.output, "w") as f:
            json.dump(comparison, f, indent=2, ensure_ascii=False)
        print(f"[DONE] Comparison written to {args.output}", file=sys.stderr)

        # Also write CSV summary if requested
        if args.csv_output:
            rows = []
            s = comparison["summary"]["overall_pass_rate"]
            cat_rows = []
            for cat, data in comparison["per_category"].items():
                r = {
                    "category": cat,
                    "baseline_total": data["total"]["baseline"],
                    "improvement_total": data["total"]["improvement"],
                    "baseline_pass_rate": data["pass_rate"]["baseline"],
                    "improvement_pass_rate": data["pass_rate"]["improvement"],
                    "delta_pct_points": data["pass_rate"]["delta_pct_points"],
                }
                cat_rows.append(r)

            if cat_rows:
                csv_fieldnames = list(cat_rows[0].keys())
                with open(args.csv_output, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=csv_fieldnames)
                    writer.writeheader()
                    writer.writerows(cat_rows)
            print(f"[DONE] Per-category CSV written to {args.csv_output}", file=sys.stderr)

    elif args.logs_dir:
        # Single run aggregation
        metrics = aggregate_single(args.logs_dir, args.dataset_list)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write JSON
        with open(args.output, "w") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False, default=str)
        print(f"[DONE] Metrics JSON written to {args.output}", file=sys.stderr)

        # Print summary to stdout
        s = metrics["run_summary"]
        print("\n" + "=" * 70)
        print("  PoCEvolve Evaluation Summary")
        print("=" * 70)
        print(f"  Total vulns evaluated: {s['total_vulns']}")
        print(f"  Completed:             {s['completed']}")
        print(f"  Incomplete/error:      {s['incomplete_or_error']}")
        print("-" * 70)
        print(f"  Passed:                {s['passed']} ({s['overall_pass_rate']:.1f}%)")
        print(f"  Failed:                {s['failed']}")
        print("-" * 70)
        print("  Per-category pass rates:")
        for cat in CATEGORIES:
            cc = metrics.get("per_category", {}).get(cat, {})
            total = cc.get("total", 0)
            rate = cc.get("pass_rate", 0)
            passed = cc.get("passed", 0)
            if total > 0:
                print(f"    {cat:30s}: {passed}/{total} = {rate:.1f}%")
        scores = metrics.get("score_statistics", {})
        if scores.get("mean_avg_score"):
            print(f"\n  Score statistics:")
            for k, v in scores.items():
                if isinstance(v, float):
                    print(f"    {k:25s}: {v:.4f}")
                else:
                    print(f"    {k:25s}: {v}")
        print("=" * 70)

        # Write CSV if requested
        if args.csv_output:
            write_csv(metrics["per_vuln"], args.csv_output)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
