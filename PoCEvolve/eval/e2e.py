#!/usr/bin/env python3
import argparse
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
    parser.add_argument("--cve-count", type=int, default=None,
                        help="Process at most N CVEs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Verify environment only, skip pipeline execution")
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

def main():
    args = parse_args()
    
    script_dir = Path(__file__).parent.resolve()
    parent_dir = script_dir.parent
    results_dir = script_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    
    dataset = Path(args.dataset) if args.dataset else parent_dir / "datasets" / "SecBench.js.PoCGen.vfc.190"
    
    if not dataset.exists():
        print(f"\033[91m[ERROR] Dataset not found: {dataset}\033[0m")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{args.mode}_{timestamp}"
    run_log = results_dir / f"{run_id}.log"
    metrics_out = results_dir / f"{run_id}_metrics.json"

    if args.cve_count and args.cve_count > 0:
        filtered_dataset = results_dir / ".filtered_dataset.txt"
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
    print(f"Mode:       {args.mode}")
    print(f"Dataset:    {active_dataset} ({total_cves} items)")
    print(f"Run ID:     {run_id}")
    print(f"Log:        {run_log}\n")

    if args.dry_run:
        phase_0_verify_env(parent_dir)
        sys.exit(0)

    env_vars = {
        "DATASET": str(active_dataset),
        "PYTHONUNBUFFERED": "1"
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
        ["python3", str(script_dir / "aggregate_metrics.py"), "--logs-dir", str(parent_dir / "logs"), "--output", str(metrics_out), "--dataset-list", str(active_dataset)],
        env_vars=env_vars, cwd=script_dir, log_file=run_log
    )

    print("\n=== Run Complete ===")
    print(f"Metrics written to: {metrics_out}")

if __name__ == "__main__":
    main()