import cProfile
import pstats
from pathlib import Path
import traceback
import glob
import json

from src.config import *
from src.utils import load_text, load_json, dump_json
from src.pipeline import run_gepa_optimization


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
    print(DATASET_LIST)

    vfcs_by_id = _load_vfcs_generated()
    print(f'Loaded {len(vfcs_by_id)} vfc entries from GENERATED_VFC_GLOB')

    ids = load_text(DATASET_LIST).splitlines()
    for id in ids:
        transcript = {"id": id}
        path_id = id.replace(":", "_")
        transcript_file = Path(GEPA_LOG_DIR) / path_id / "transcript.json"

        if transcript_file.exists():
            _transcript = load_json(str(transcript_file))
            if "error" not in _transcript:
                print(f'No error in {id}. Skip.')
                continue
            if _transcript_succeeded(_transcript):
                print(f'Already succeeded in previous evolver run for {id}. Skip.')
                continue
            if "attempts" in _transcript:
                transcript['attempts'] = _transcript['attempts']

        datapoint = vfcs_by_id.get(path_id)
        if datapoint is None:
            print(f'No generated VFC entry for {id}. Skip.')
            continue

        if _llm_exploit_succeeded(datapoint):
            print(f'LLM already succeeded for {id}. Skip.')
            continue

        try:
            if 'generated_exploits' in datapoint:
                run_gepa_optimization(datapoint, transcript)

        except KeyboardInterrupt:
            transcript.update({"error": {"message": "KeyboardInterrupt", "trackback": ""}})
        except Exception as e:
            transcript.update({"error": {
                "message": str(e),
                "trackback": traceback.format_exc()
            }})
            print(f"Error during optimization: {str(e)}")
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
