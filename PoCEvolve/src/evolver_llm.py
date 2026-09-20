import os
import cProfile
import pstats
from pathlib import Path
import traceback
import glob
import json
import time

from .config import *
from .utils import load_text, load_json, dump_json
from .pipeline import run_gepa_optimization
from tqdm import tqdm


def _llm_exploit_succeeded(datapoint: dict) -> bool:
    for exploit in datapoint.get('generated_exploits', []):
        for run in (exploit.get('console_log') or []):
            if 'pass 1' in run.get('stdout', ''):
                return True
    return False


def _transcript_succeeded(transcript: dict) -> bool:
    for attempt in transcript.get('attempts', []):
        for prompt in (attempt.get('seed_prompts') or []):
            if prompt.get('exploit_result'):
                return True
    return False


def _load_vfcs_generated() -> dict:
    vfcs_by_id: dict = {}
    for file_path in glob.glob(GENERATED_VFC_GLOB):
        with open(file_path, 'r') as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    datapoint = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"Skipping invalid JSON in {file_path}:{line_no} -> {e}")
                    continue
                testbed_dir = datapoint.get('testbed_dir')
                if testbed_dir:
                    vfcs_by_id[testbed_dir] = datapoint
    return vfcs_by_id


def main():
    if SKIP_GEPA:
        print("[SKIP] GEPA (Phase 3) is disabled via SKIP_GEPA=1 — moving on to Phase 4.")
        return

    print(DATASET_LIST)

    vfcs_by_id = _load_vfcs_generated()
    print(f'Loaded {len(vfcs_by_id)} vfc entries from GENERATED_VFC_GLOB')

    ids = load_text(DATASET_LIST).splitlines()

    # Apply CVE_COUNT limit if set (via env var, controlled by run_pipeline.py)
    cve_count = os.getenv("CVE_COUNT")
    if cve_count:
        n = int(cve_count)
        print(f"[INFO] CVE_COUNT={n}: limiting to first {n} CVEs")
        ids = ids[:n]

    total = len(ids)

    # Count already-completed transcripts for progress initial value
    completed = 0
    for id in ids:
        transcript_file = Path(GEPA_LOG_DIR) / id.replace(":", "_") / "transcript.json"
        if transcript_file.exists():
            _transcript = load_json(str(transcript_file))
            if "error" not in _transcript or _transcript_succeeded(_transcript):
                completed += 1

    print(f"Processing {total} CVEs ({completed} already done, {total - completed} remaining)")

    try:
        # Wrap the main loop in tqdm directly for cleaner initialization
        for id in tqdm(ids, desc="Evolver LLM", unit="CVE"):
            path_id = id.replace(":", "_")
            transcript_file = Path(GEPA_LOG_DIR) / path_id / "transcript.json"

            if transcript_file.exists():
                _transcript = load_json(str(transcript_file))
                
                # Check if the transcript is corrupt (e.g. empty attempts from an interrupted run)
                has_valid_attempts = any(
                    len(att.get('seed_prompts', [])) > 0 
                    for att in _transcript.get('attempts', [])
                )

                if "error" not in _transcript and has_valid_attempts:
                    tqdm.write(f'  [SKIP] {id}: No error in transcript (completed).')
                    continue
                if _transcript_succeeded(_transcript):
                    tqdm.write(f'  [SKIP] {id}: Already succeeded in previous evolver run.')
                    continue
                
                if not has_valid_attempts:
                    tqdm.write(f'  [CLEANUP] {id}: Found incomplete/corrupted transcript from prior interruption. Resetting...')
                    transcript = {}
                else:
                    transcript = dict(_transcript)
            else:
                transcript = {}

            datapoint = vfcs_by_id.get(path_id)
            if datapoint is None:
                tqdm.write(f'  [SKIP] {id}: No generated VFC entry found.')
                continue

            if _llm_exploit_succeeded(datapoint):
                tqdm.write(f'  [SKIP] {id}: LLM already succeeded in Phase 2.')
                continue

            try:
                # Write current CVE to temp file so external trackers can display it
                cve_file = os.getenv("CURRENT_CVE_FILE")
                if cve_file:
                    with open(cve_file, "w") as f:
                        f.write(id)

                if 'generated_exploits' in datapoint:
                    start_time = time.time()
                    tqdm.write(f"  → [{id}] Starting GEPA optimization loop..."
                    )
                    
                    # Execute the actual iteration loop
                    run_gepa_optimization(datapoint, transcript)
                    
                    elapsed = time.time() - start_time
                    
                    if _transcript_succeeded(transcript):
                        tqdm.write(f"\r  → [{id}] GEPA optimization: \033[92mPASSED\033[0m ({elapsed:.1f}s)")
                    else:
                        tqdm.write(f"\r  → [{id}] GEPA optimization: \033[93mFINISHED\033[0m ({elapsed:.1f}s)")

            except KeyboardInterrupt:
                transcript.update({"error": {"message": "KeyboardInterrupt", "trackback": ""}})
                raise
            except Exception as e:
                transcript.update({"error": {
                    "message": str(e),
                    "trackback": traceback.format_exc()
                }})
                tqdm.write(f"\n  → [{id}] \033[91mERROR\033[0m during optimization: {str(e)}")
            finally:
                transcript.update({
                    "testbed": str(Path(TESTBED_DIR) / path_id),
                    "command_timeout": COMMAND_TIMEOUT,
                    "max_iteration": ITERATION,
                    "minibatch_size": MINIBATCH_SIZE,
                    "model": MODEL_NAME,
                    "seed": SEED
                })
                transcript_file = Path(GEPA_LOG_DIR) / path_id / "transcript.json"
                transcript_file.parent.mkdir(parents=True, exist_ok=True)
                dump_json(transcript, transcript_file)
                
    except Exception as fatal_e:
        print(f"\nFatal Evolver Error: {fatal_e}")


if __name__ == "__main__":

    profiler = cProfile.Profile()
    profiler.enable()

    main()

    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats("tottime")

    log_file = Path(GEPA_LOG_DIR) / f"profiling_results_{DATASET_LIST.replace('/', '.')}"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    with open(log_file, "w") as f:
        stats.stream = f
        stats.print_stats()

    print(f"\nProfiling results written to {log_file}")