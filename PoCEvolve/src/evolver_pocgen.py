import os
import cProfile
import pstats
from pathlib import Path
import traceback

from src.config import *
from src.utils import load_text, load_json, dump_json
from src.pipeline import run_gepa_optimization
from tqdm import tqdm

def _transcript_succeeded(transcript: dict) -> bool:
    for attempt in transcript.get('attempts', []):
        for prompt in (attempt.get('seed_prompts') or []):
            if prompt.get('exploit_result'):
                return True
    return False


def main():
    if SKIP_GEPA:
        print("[SKIP] GEPA (Phase 3) is disabled via SKIP_GEPA=1 — moving on to Phase 4.")
        return

    print(DATASET_LIST)
    training_data_path = Path(TRAINING_DATA)


    ids = load_text(DATASET_LIST).splitlines()

    # Apply CVE_COUNT limit if set (via env var, controlled by run_pipeline.sh)
    cve_count = os.getenv("CVE_COUNT")
    if cve_count:
        n = int(cve_count)
        print(f"[INFO] CVE_COUNT={n}: limiting to first {n} CVEs", flush=True)
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

    print(f"Processing {total} CVEs ({completed} already done, {total - completed} remaining)", flush=True)

    progress = tqdm(total=total, desc="Evolver PoCGen", unit="CVE")

    try:
        for id in ids:
            id_raw = id
            transcript = {"id": id}
            id = id.replace(":", "_")
            transcript_file = Path(GEPA_LOG_DIR) / id / "transcript.json"


            if transcript_file.exists():
                _transcript = load_json(str(transcript_file))
                if "error" not in _transcript:
                    print(f'No error in {id_raw}. Skip.')
                    continue
                if _transcript_succeeded(_transcript):
                    print(f'Already succeeded in previous evolver run for {id_raw}. Skip.')
                    continue
                if "attempts" in _transcript:
                    transcript['attempts'] = _transcript['attempts']


            id_data_path = training_data_path / f"{id}.json"
            if not id_data_path.exists():
                print(f'No training input for {id}. Skip.')
                continue


            data = load_json(str(id_data_path))



            try:
                # Write current CVE to temp file so bash spinner can display it
                cve_file = os.getenv("CURRENT_CVE_FILE")
                if cve_file:
                    with open(cve_file, "w") as f:
                        f.write(id_raw)

                print(id)
                run_gepa_optimization(data, transcript)
            except KeyboardInterrupt:
                transcript.update({"error": {"message": "KeyboardInterrupt", "trackback": ""}})
                raise
            except Exception as e:
                transcript.update({"error": {
                    "message": str(e),
                    "trackback": traceback.format_exc()
                }})
                print(f"Error during optimization: {str(e)}")
            finally:
                transcript.update({
                    "testbed": str(Path(TESTBED_DIR) / id),
                    "command_timeout": COMMAND_TIMEOUT,
                    "max_iteration": ITERATION,
                    "minibatch_size": MINIBATCH_SIZE,
                    "model": MODEL_NAME,
                    "seed": SEED
                })
                transcript_file = Path(GEPA_LOG_DIR) / id /"transcript.json"
                transcript_file.parent.mkdir(parents=True, exist_ok=True)
                dump_json(transcript, transcript_file)
                progress.update(1)
    finally:
        progress.close()


if __name__ == "__main__":

    profiler = cProfile.Profile()
    profiler.enable()

    main()

    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats("tottime")

    log_file = Path(GEPA_LOG_DIR) / f"profiling_results{DATASET_LIST.replace('/', '.')}"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    with open(log_file, "w") as f:
        stats.stream = f
        stats.print_stats()

    print(f"Profiling results written to {log_file}")
