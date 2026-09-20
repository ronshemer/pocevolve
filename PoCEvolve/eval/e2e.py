#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import os
import shutil
import threading
import queue
from pathlib import Path
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate PoCEvolve pipeline end-to-end")
    parser.add_argument("--mode", choices=["baseline", "improvement"], default="baseline",
                        help="Run mode (default: baseline)")
    parser.add_argument("--dataset", type=str, default=None,
                        help="Path to dataset file")
    parser.add_argument("--vulnerability-type", type=str, default=None,
                        help="Only run records of this type (for example: command-injection)")
    parser.add_argument("--cve", type=str, default=None,
                        help="CVE identifier to run (e.g. SNYK-JS-ALFREDWORKFLOWNODEJS-608975 or GHSA-9jm3-5835-537m).")
    parser.add_argument("--cve-count", type=int, default=None,
                        help="Process at most N CVEs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Verify environment only, skip pipeline execution")
    parser.add_argument("--resume-dir", type=str, default=None,
                        help="Path to an existing run directory to resume")
    parser.add_argument("--skip-gepa", action="store_true",
                        help="Skip GEPA optimization (default: skip)")
    parser.add_argument("--run-gepa", action="store_true",
                        help="Explicitly re-enable GEPA optimization (overriding default skip)")
    return parser.parse_args()

def stream_command(cmd, env_vars=None, cwd=None, log_file=None):
    """Executes a shell command with a live spinner while waiting for output."""
    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    print(f"\033[90m> {' '.join(cmd)}\033[0m")
    
    proc = subprocess.Popen(
        cmd, env=env, cwd=cwd, 
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
        text=True, bufsize=1
    )

    # Use a queue to safely pass output from the reader thread to the main thread
    q = queue.Queue()

    def enqueue_output(out, queue):
        for line in out:
            queue.put(line)
        queue.put(None)  # EOF marker

    t = threading.Thread(target=enqueue_output, args=(proc.stdout, q))
    t.daemon = True
    t.start()

    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    spin_idx = 0

    with open(log_file, 'a') if log_file else open(os.devnull, 'w') as f_log:
        while True:
            try:
                # Wait briefly for output; if none, update spinner
                line = q.get(timeout=0.1)
                if line is None:
                    break
                
                # Clear the spinner line before printing actual output
                sys.stdout.write('\r\033[K')
                sys.stdout.write(line)
                sys.stdout.flush()
                f_log.write(line)
            except queue.Empty:
                # Animate spinner
                sys.stdout.write(f"\r\033[96m{spinner[spin_idx]} Working...\033[0m")
                sys.stdout.flush()
                spin_idx = (spin_idx + 1) % len(spinner)
                
    # Clear spinner cleanly when done
    sys.stdout.write('\r\033[K')
    sys.stdout.flush()

    proc.wait()
    if proc.returncode != 0:
        print(f"\033[91m[ERROR] Command failed with exit code {proc.returncode}\033[0m")
        sys.exit(proc.returncode)

def phase_0_verify_env(parent_dir):
    print("\n=== Phase 0: Environment Verification ===")
    errors = 0
    
    if not shutil.which("docker"):
        print("[FAIL] Docker not found.")
        errors += 1
    else:
        try:
            subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[OK] Docker daemon is responsive.")
        except subprocess.CalledProcessError:
            print("[FAIL] Docker daemon is not running.")
            errors += 1
            
    try:
        import litellm 
        print("[OK] Python dependencies found.")
    except ImportError:
        print("[WARN] litellm module not found in current environment.")

    if errors > 0:
        print(f"\033[91m[ABORTED] {errors} critical errors found.\033[0m")
        sys.exit(1)
    print("\033[92m[PASS] Environment ready.\033[0m")


def _preflight_cve_check(run_dir, cve_ids, script_dir):
    """Validate that requested CVE IDs exist in the underlying source data.

    The pipeline reads from ``secbenchjs/vfcs.filtered.json`` (or an existing
    ``vfcs.predicted.json`` from a previous run).  If a CVE ID is listed in the
    dataset but missing from the source JSON, the whole run silently processes
    zero items — this check catches that early.
    """
    # Prefer recent predictions; fall back to the base filtered data.
    predicted = run_dir / "vfcs.predicted.json"
    if predicted.exists():
        try:
            import json as _json
            data = _json.loads(predicted.read_text())
            available = {d.get("testbed_dir", d.get("id", "")) for d in data}
            source_desc = str(predicted)
        except Exception:
            available, source_desc = None, "vfcs.predicted.json (read failed)"
    else:
        src_path = script_dir.parent / "secbenchjs" / "vfcs.filtered.json"
        if src_path.exists():
            try:
                import json as _json
                data = _json.loads(src_path.read_text())
                available = {d.get("testbed_dir", d.get("id", "")) for d in data}
                source_desc = str(src_path)
            except Exception:
                available, source_desc = None, f"{src_path} (read failed)"
        else:
            available, source_desc = None, "secbenchjs/vfcs.filtered.json"

    if available is None:
        print(f"\033[93m[WARN] Could not read source data ({source_desc}) — skipping pre-flight CVE check.\033[0m")
        return []

    # Normalise IDs the same way the pipeline does (colon→underscore).
    def _normalise(raw):
        return raw.replace(":", "_").strip()

    missing = [cid for cid in cve_ids if _normalise(cid) not in available]

    if not missing:
        print(f"\033[92m[OK] All {len(cve_ids)} CVE(s) found in {Path(source_desc).name}.\033[0m")
    else:
        print(f"\033[91m[ERROR] {len(missing)} CVE(s) not found in source data ({Path(source_desc).name}):")
        for m in missing:
            print(f"  - {m}")
        print("\nThese CVEs exist in the dataset list but have no entries in the underlying data.")
        print("Re-run with a different --cve or update secbenchjs/vfcs.filtered.json.")

    return missing


def _normalise_dataset_id(value):
    return str(value or "").strip().replace(":", "_")


def _filter_by_vulnerability_type(dataset, script_dir, vulnerability_type, output_path):
    """Filter a newline-delimited ID dataset using the generated VFCS metadata."""
    # Match the same source consumed by src.analyzer. Looking through the broader
    # files can overwrite an ID with a different category when SecBench contains
    # the same advisory in more than one vulnerability directory.
    source_candidates = (script_dir.parent / "secbenchjs" / "vfcs.filtered.json",)
    records_by_id = {}
    source_name = None
    for source_path in source_candidates:
        if not source_path.exists():
            continue
        try:
            records = json.loads(source_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        source_name = source_path.name
        for record in records:
            if not isinstance(record, dict):
                continue
            ids = list(record.get("ids") or [])
            if record.get("testbed_dir"):
                ids.append(record["testbed_dir"])
            for identifier in ids:
                records_by_id.setdefault(_normalise_dataset_id(identifier), record)

    if not records_by_id:
        print(f"\033[91m[ERROR] Cannot apply --vulnerability-type: no VFCS metadata found.\033[0m")
        sys.exit(1)

    wanted = vulnerability_type.strip().lower()
    selected = []
    unmatched = []
    with open(dataset, encoding="utf-8") as source:
        for line in source:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            identifier = line.strip()
            record = records_by_id.get(_normalise_dataset_id(identifier))
            if record is None:
                unmatched.append(identifier)
                continue
            if str(record.get("vulnerability_type", "")).strip().lower() == wanted:
                selected.append(line)

    if not selected:
        print(f"\033[91m[ERROR] No records of vulnerability type '{vulnerability_type}' found in {dataset}.\033[0m")
        if unmatched:
            print(f"[WARN] {len(unmatched)} dataset IDs were not found in VFCS metadata ({source_name}).")
        sys.exit(1)

    output_path.write_text("".join(selected), encoding="utf-8")
    print(f"Filtering to vulnerability type: {vulnerability_type} ({len(selected)} items; metadata: {source_name})")
    if unmatched:
        print(f"[WARN] {len(unmatched)} dataset IDs were not found in VFCS metadata and were excluded.")
    return output_path

def main():
    args = parse_args()
    
    script_dir = Path(__file__).parent.resolve()
    parent_dir = script_dir.parent
    
    # Setup Run Directory
    if args.resume_dir:
        run_dir = Path(args.resume_dir).resolve()
        if not run_dir.exists():
            print(f"\033[91m[ERROR] Resume directory not found: {run_dir}\033[0m")
            sys.exit(1)
        run_id = run_dir.name
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_id = f"{args.mode}_{timestamp}"
        run_dir = script_dir / "results" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
    
    run_log = run_dir / f"{run_id}.log"
    metrics_out = run_dir / f"{run_id}_metrics.json"

    dataset = Path(args.dataset) if args.dataset else parent_dir / "datasets" / "SecBench.js.PoCGen.vfc.190"
    if not dataset.exists():
        print(f"\033[91m[ERROR] Dataset not found: {dataset}\033[0m")
        sys.exit(1)

    if args.vulnerability_type:
        type_dataset = run_dir / ".type_filtered_dataset.txt"
        dataset = _filter_by_vulnerability_type(dataset, script_dir, args.vulnerability_type, type_dataset)

    if args.cve:
        print(f"Filtering to CVE: {args.cve}")
        filtered_dataset = run_dir / ".filtered_dataset.txt"
        with open(dataset, 'r') as f_in, open(filtered_dataset, 'w') as f_out:
            matching = []
            for l in f_in.readlines():
                stripped = l.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if args.cve in stripped:
                    matching.append(l)
                    f_out.write(l)
        if not matching:
            print(f"\033[91m[ERROR] CVE identifier '{args.cve}' not found in {dataset}\033[0m")
            sys.exit(1)
        active_dataset = filtered_dataset
        total_cves = len(matching)
    elif args.cve_count and args.cve_count > 0:
        filtered_dataset = run_dir / ".filtered_dataset.txt"
        with open(dataset, 'r') as f_in, open(filtered_dataset, 'w') as f_out:
            lines = [l for l in f_in.readlines() if l.strip()]
            f_out.writelines(lines[:args.cve_count])
        active_dataset = filtered_dataset
        total_cves = args.cve_count
    else:
        active_dataset = dataset
        with open(dataset, 'r') as f:
            total_cves = len([l for l in f.readlines() if l.strip()])

    print("=== PoCEvolve Evaluation Run ===")
    print(f"Run Dir:    {run_dir}")
    print(f"Mode:       {args.mode}")
    print(f"Dataset:    {active_dataset} ({total_cves} items)")
    print(f"Run ID:     {run_id}")
    print(f"Log:        {run_log}\n")

    if args.dry_run:
        phase_0_verify_env(parent_dir)
        sys.exit(0)

    # Preflight: check that requested CVEs exist in the underlying source data.
    if args.cve or (args.cve_count and args.cve_count > 0):
        cve_ids = [l.strip() for l in Path(active_dataset).read_text().splitlines() if l.strip()]
        missing = _preflight_cve_check(run_dir, cve_ids, script_dir)
        if missing:
            sys.exit(1)

    # Determine SKIP_GEPA: --run-gepa overrides everything → --skip-gepa respects env → default "1" (skip)
    if args.run_gepa and not args.skip_gepa:
        # Explicit --run-gepa: disable skip (env var is overridden)
        skip_gepa = "0"
    else:
        # --skip-gepa or no flag: respect env var → default "1"
        skip_gepa = os.environ.get("SKIP_GEPA", "1")

    env_vars = {
        "DATASET": str(active_dataset),
        "PYTHONUNBUFFERED": "1",
        "RUN_OUTPUT_DIR": str(run_dir),  # Pass the directory to child processes
        "SKIP_GEPA": skip_gepa,
    }
    
    if args.mode == "improvement":
        env_vars["USE_STATIC_ANALYSIS"] = "true"

    phase_0_verify_env(parent_dir)

    print(f"\n=== Phase 1: Vulnerability Analysis ===")
    stream_command(["python3", "-B", "-m", "src.analyzer"], env_vars=env_vars, cwd=parent_dir, log_file=run_log)

    print(f"\n=== Phase 2: VFC Generation ===")
    stream_command(["python3", "-B", "-m", "src.generator"], env_vars=env_vars, cwd=parent_dir, log_file=run_log)

    print(f"\n=== Phase 3: Exploit Evolution ===")
    evolver_script = "src.evolver_llm" if "vfc" in dataset.name else "src.evolver_pocgen"
    stream_command(["python3", "-B", "-m", evolver_script], env_vars=env_vars, cwd=parent_dir, log_file=run_log)

    print(f"\n=== Phase 4: Metrics Aggregation ===")
    stream_command(
        ["python3", str(script_dir / "aggregate_metrics.py"), "--logs-dir", str(run_dir), "--output", str(metrics_out), "--dataset-list", str(active_dataset)],
        env_vars=env_vars, cwd=script_dir, log_file=run_log
    )

    print("\n=== Run Complete ===")
    print(f"Metrics written to: {metrics_out}")

if __name__ == "__main__":
    main()
